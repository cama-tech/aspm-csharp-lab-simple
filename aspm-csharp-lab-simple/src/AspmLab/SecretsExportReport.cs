public sealed record SecretsExportSummary(
    int ExpectedCases, int PassedCases, int FailedCases, int PendingCases,
    int ImportedFindings, int UnmappedFindings);

public sealed record SecretsExportReport(
    DateTimeOffset GeneratedAtUtc, Guid TestRunId, SecretsExportSummary Summary,
    IReadOnlyList<LabExecutionResult> Results)
{
    private static readonly SecretExportCase[] Expected =
    {
        new("SECRET-CRITICAL-001", "critical", true),
        new("SECRET-HIGH-001", "high", true),
        new("SECRET-MEDIUM-001", "medium", true),
        new("SECRET-LOW-001", "low", true),
        new("SECRET-FP-001", "none", false)
    };

    public static SecretsExportReport Create(IReadOnlyList<LabExecutionResult> results, Guid testRunId)
    {
        var output = results.ToList();
        var passed = 0; var failed = 0; var pending = 0;
        foreach (var item in Expected)
        {
            var matches = results.Where(result => result.CaseId == item.CaseId).ToList();
            if (matches.Any(result => result.Passed == false)) failed++;
            else if (matches.Any(result => result.Passed == true)) passed++;
            else
            {
                pending++;
                output.Add(Pending(item, testRunId));
            }
        }
        return new SecretsExportReport(DateTimeOffset.UtcNow, testRunId,
            new SecretsExportSummary(Expected.Length, passed, failed, pending,
                results.Count(result => result.Method == "SECRETS-IMPORT"),
                results.Count(result => result.CaseId == "SECRET-UNMAPPED")),
            output.OrderBy(result => result.CaseId).ThenBy(result => result.TimestampUtc).ToList());
    }

    private static LabExecutionResult Pending(SecretExportCase item, Guid testRunId)
    {
        var evidence = new Dictionary<string, string?>
        {
            ["detected"] = "False", ["validationStatus"] = "pending",
            ["expectedDetection"] = item.ExpectedDetection.ToString()
        };
        return new LabExecutionResult(
            Guid.NewGuid(), DateTimeOffset.UtcNow, item.CaseId, "SECRETS-PENDING",
            item.ExpectedDetection ? "fixtures/secrets/detectable-secrets.env" : "fixtures/secrets/known-false-positives.txt",
            "[REDACTED]", "Import the Gitleaks JSON and validate this controlled case.",
            "No secrets result has been imported for this case.", null, null,
            "Pending is not a failed test.", "Gitleaks", Severity: item.Severity,
            Source: "secrets", TestRunId: testRunId,
            Assertion: "Import scanner evidence before evaluating this case.", Evidence: evidence);
    }

    private sealed record SecretExportCase(string CaseId, string Severity, bool ExpectedDetection);
}
