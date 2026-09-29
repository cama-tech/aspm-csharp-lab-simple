using System.Text.Json;

public static class SecretsImporter
{
    private static readonly SecretCase[] Expected =
    {
        new("SECRET-CRITICAL-001", "lab-aws-access-key", "critical", true),
        new("SECRET-HIGH-001", "lab-github-token", "high", true),
        new("SECRET-MEDIUM-001", "lab-password", "medium", true),
        new("SECRET-LOW-001", "lab-internal-key", "low", true),
        new("SECRET-FP-001", "public-documentation-id", "none", false)
    };

    public static async Task<SecretsImportSummary> ImportAsync(Stream stream, LabResultStore store)
    {
        using var document = await JsonDocument.ParseAsync(stream);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new JsonException("The Gitleaks document must be a JSON array.");

        var imported = 0;
        var mapped = 0;
        var unmapped = 0;
        foreach (var finding in document.RootElement.EnumerateArray())
        {
            var ruleId = Read(finding, "RuleID") ?? Read(finding, "RuleId") ?? "unknown-rule";
            var expected = Expected.FirstOrDefault(item => item.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase));
            var caseId = expected?.CaseId ?? "SECRET-UNMAPPED";
            if (expected is null) unmapped++; else mapped++;
            var file = Read(finding, "File") ?? "unknown-file";
            var line = ReadInt(finding, "StartLine");
            var fingerprint = Read(finding, "Fingerprint");
            var evidence = new Dictionary<string, string?>
            {
                ["ruleId"] = ruleId,
                ["file"] = file,
                ["line"] = line?.ToString(),
                ["fingerprint"] = fingerprint,
                ["detected"] = "True",
                ["expectedDetection"] = expected?.ExpectedDetection.ToString(),
                ["classification"] = expected?.ExpectedDetection == false ? "false_positive" : "true_positive"
            };
            bool? passed = expected is null ? null : expected.ExpectedDetection;
            store.Add(new LabExecutionResult(
                Guid.NewGuid(), DateTimeOffset.UtcNow, caseId, "SECRETS-IMPORT", file,
                "[REDACTED]", expected?.ExpectedDetection == false
                    ? "Preserve and classify the public example as a false positive."
                    : "Detect the expected synthetic secret without exporting its value.",
                $"Gitleaks reported rule {ruleId} at {file}:{line}.", passed, null,
                expected?.ExpectedDetection == false
                    ? "The expected false-positive example was detected and requires classification."
                    : "Imported and matched the expected secrets case.",
                "Gitleaks", null, ruleId, expected?.Severity, file, line,
                Read(finding, "Description"), "secrets", TestRunId: store.TestRunId,
                Assertion: expected?.ExpectedDetection == false
                    ? "The token-shaped public example must be classified as a false positive."
                    : "The expected synthetic secret must be detected.",
                Evidence: evidence));
            imported++;
        }

        AddMissingResults(store);
        return new SecretsImportSummary(imported, mapped, unmapped);
    }

    private static void AddMissingResults(LabResultStore store)
    {
        var results = store.GetSecrets();
        foreach (var item in Expected)
        {
            if (results.Any(result => result.CaseId == item.CaseId)) continue;
            var isNegativeControl = !item.ExpectedDetection;
            var evidence = new Dictionary<string, string?>
            {
                ["ruleId"] = item.RuleId,
                ["detected"] = "False",
                ["expectedDetection"] = item.ExpectedDetection.ToString(),
                ["classification"] = isNegativeControl ? "false_positive_control" : "true_positive"
            };
            store.Add(new LabExecutionResult(
                Guid.NewGuid(), DateTimeOffset.UtcNow, item.CaseId, "SECRETS-VALIDATION",
                isNegativeControl ? "fixtures/secrets/known-false-positives.txt" : "fixtures/secrets/detectable-secrets.env",
                "[REDACTED]", isNegativeControl
                    ? "The allowlisted public example must not be reported as a confirmed secret."
                    : "The expected synthetic secret must be detected.",
                isNegativeControl ? "The allowlisted example was not reported." : "The expected secret was not found.",
                isNegativeControl, null,
                isNegativeControl ? "The false-positive control behaved as expected." : "Expected secret missing from imported results.",
                "Gitleaks", null, item.RuleId, item.Severity, null, null, null, "secrets",
                TestRunId: store.TestRunId,
                Assertion: isNegativeControl ? "Allowlisted example remains excluded." : "Expected rule must appear.",
                FailureReason: isNegativeControl ? null : $"Gitleaks did not report rule {item.RuleId}.",
                Evidence: evidence));
        }
    }

    private static string? Read(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static int? ReadInt(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) ? number : null;

    private sealed record SecretCase(string CaseId, string RuleId, string Severity, bool ExpectedDetection);
}

public sealed record SecretsImportSummary(int ImportedFindings, int MappedFindings, int UnmappedFindings);
