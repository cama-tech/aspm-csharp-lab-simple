using System.Text.Json;

public sealed record IacImportSummary(int FailedChecksScanned, int Imported, int Mapped, int Unmapped);

public static class IacImporter
{
    private static readonly ExpectedIacCase[] Expected =
    {
        new("IAC-CRITICAL-001", "aws_security_group.database", "critical"),
        new("IAC-HIGH-001", "aws_s3_bucket_public_access_block.aspm_lab", "high"),
        new("IAC-MEDIUM-001", "aws_vpc.lab", "medium"),
        new("IAC-LOW-001", "aws_security_group_rule.all_egress", "low")
    };

    public static async Task<IacImportSummary> ImportAsync(Stream stream, LabResultStore store)
    {
        using var document = await JsonDocument.ParseAsync(stream);
        var root = document.RootElement;
        var results = root.TryGetProperty("results", out var resultNode) ? resultNode : root;
        if (!results.TryGetProperty("failed_checks", out var failedNode) || failedNode.ValueKind != JsonValueKind.Array)
            throw new JsonException("Checkov results.failed_checks array is required.");

        var checks = failedNode.EnumerateArray().ToList();
        var mappedCaseIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var mapped = 0;
        var unmapped = 0;
        var localhostPublicExposure = false;

        foreach (var check in checks)
        {
            var resource = Text(check, "resource") ?? "unknown";
            var expected = Expected.FirstOrDefault(item => resource.Equals(item.Resource, StringComparison.OrdinalIgnoreCase));
            var caseId = expected?.CaseId ?? "IAC-UNMAPPED";
            if (expected is null) unmapped++; else { mapped++; mappedCaseIds.Add(caseId); }

            if (resource.Equals("aws_security_group.localhost_service", StringComparison.OrdinalIgnoreCase) &&
                LooksLikePublicExposure(check)) localhostPublicExposure = true;

            store.Add(CreateFinding(store, check, caseId, expected?.Severity, expected is null ? null : true));
        }

        foreach (var expected in Expected.Where(item => !mappedCaseIds.Contains(item.CaseId)))
            store.Add(CreateMissing(store, expected));

        store.Add(CreateFalsePositive(store, localhostPublicExposure));
        return new IacImportSummary(checks.Count, checks.Count + Expected.Length - mappedCaseIds.Count + 1,
            mapped + Expected.Length - mappedCaseIds.Count + 1, unmapped);
    }

    private static LabExecutionResult CreateFinding(LabResultStore store, JsonElement check,
        string caseId, string? expectedSeverity, bool? passed)
    {
        var checkId = Text(check, "check_id");
        var checkName = Text(check, "check_name");
        var resource = Text(check, "resource");
        var file = Text(check, "file_path")?.TrimStart('/') ?? "infra/main.tf";
        var line = FirstLine(check);
        var observedSeverity = Text(check, "severity");
        var evidence = new Dictionary<string, string?>
        {
            ["detected"] = "True", ["checkId"] = checkId, ["checkName"] = checkName,
            ["resource"] = resource, ["file"] = file, ["line"] = line?.ToString(),
            ["expectedSeverity"] = expectedSeverity, ["observedSeverity"] = observedSeverity ?? "not_provided"
        };
        return new LabExecutionResult(Guid.NewGuid(), DateTimeOffset.UtcNow, caseId, "IAC-IMPORT",
            file, resource ?? string.Empty, "Detect the controlled Terraform misconfiguration.",
            $"Checkov failed check {checkId} on {resource}.", passed, null,
            expectedSeverity is null ? "Unmapped Checkov finding requires manual review." : "Mapped Checkov finding.",
            "Checkov", RuleId: checkId, Severity: observedSeverity ?? expectedSeverity,
            File: file, Line: line, Message: checkName, Source: "iac", TestRunId: store.TestRunId,
            Assertion: expectedSeverity is null ? "Review the additional Checkov finding." : "The expected resource has at least one failed Checkov check.",
            Evidence: evidence);
    }

    private static LabExecutionResult CreateMissing(LabResultStore store, ExpectedIacCase item)
    {
        var evidence = new Dictionary<string, string?>
        {
            ["detected"] = "False", ["resource"] = item.Resource,
            ["expectedSeverity"] = item.Severity, ["validationStatus"] = "failed"
        };
        return new LabExecutionResult(Guid.NewGuid(), DateTimeOffset.UtcNow, item.CaseId, "IAC-IMPORT",
            "infra/main.tf", item.Resource, "Checkov must detect the controlled Terraform case.",
            "No failed Checkov check was imported for the expected resource.", false, null,
            "Expected IaC case was not detected.", "Checkov", Severity: item.Severity,
            File: "infra/main.tf", Source: "iac", TestRunId: store.TestRunId,
            Assertion: "The expected resource appears in Checkov failed_checks.",
            FailureReason: "The expected resource was absent from failed_checks.", Evidence: evidence);
    }

    private static LabExecutionResult CreateFalsePositive(LabResultStore store, bool incorrectlyReported)
    {
        var passed = !incorrectlyReported;
        return new LabExecutionResult(Guid.NewGuid(), DateTimeOffset.UtcNow, "IAC-FP-001", "IAC-IMPORT",
            "infra/false-positive.tf", "aws_security_group.localhost_service (127.0.0.1/32)",
            "The localhost-only rule must not be classified as public Internet exposure.",
            passed ? "No public-exposure finding was reported for localhost." : "Checkov classified localhost as public exposure.",
            passed, null, "Controlled IaC negative case.", "Checkov", Severity: "informational",
            File: "infra/false-positive.tf", Source: "iac", TestRunId: store.TestRunId,
            Assertion: "127.0.0.1/32 is not treated as 0.0.0.0/0.",
            FailureReason: passed ? null : "The localhost-only resource was reported as publicly exposed.",
            Evidence: new Dictionary<string, string?>
            {
                ["detected"] = incorrectlyReported.ToString(), ["expectedDetection"] = "False",
                ["cidr"] = "127.0.0.1/32", ["validationStatus"] = passed ? "passed" : "failed"
            });
    }

    private static bool LooksLikePublicExposure(JsonElement check)
    {
        var text = $"{Text(check, "check_name")} {check.GetRawText()}";
        return text.Contains("0.0.0.0/0", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("public", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("internet", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("unrestricted", StringComparison.OrdinalIgnoreCase);
    }

    private static int? FirstLine(JsonElement check)
    {
        if (!check.TryGetProperty("file_line_range", out var range) || range.ValueKind != JsonValueKind.Array || range.GetArrayLength() == 0)
            return null;
        return range[0].ValueKind == JsonValueKind.Number ? range[0].GetInt32() : null;
    }

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private sealed record ExpectedIacCase(string CaseId, string Resource, string Severity);
}
