public sealed record SastExportSummary(
    int ExpectedCases, int PassedCases, int FailedCases, int PendingCases,
    int ImportedFindings, int UnmappedFindings);

public sealed record SastExportReport(
    DateTimeOffset GeneratedAtUtc, Guid TestRunId, SastExportSummary Summary,
    IReadOnlyList<LabExecutionResult> Results)
{
    private static readonly SastCase[] Expected =
    {
        new("NEW-SAST-001", "critical", "Controlled command execution", true),
        new("BASELINE-SAST-001", "high", "Reflected XSS", true),
        new("BASELINE-SAST-002", "medium", "Open redirect", true),
        new("BASELINE-SAST-003", "high", "Path traversal", true),
        new("MEDIUM-SAST-001", "medium", "Sensitive information in logs", true),
        new("LOW-SAST-001", "low", "Unsafe deserialization", true),
        new("SAST-FP-001", "low", "Public documentation identifier", false)
    };

    public static SastExportReport Create(IReadOnlyList<LabExecutionResult> results, Guid testRunId)
    {
        var scannerResults = results.Where(result =>
            result.Method == "SAST-SARIF" ||
            result.Source.Equals("sarif", StringComparison.OrdinalIgnoreCase)).ToList();
        var output = scannerResults.ToList();
        var passed = 0; var failed = 0; var pending = 0;
        foreach (var item in Expected)
        {
            var matches = scannerResults.Where(result => result.CaseId == item.CaseId).ToList();
            if (matches.Any(result => result.Passed == false)) failed++;
            else if (matches.Any(result => result.Passed == true)) passed++;
            else
            {
                pending++;
                output.Add(Pending(item, testRunId));
            }
        }

        return new SastExportReport(DateTimeOffset.UtcNow, testRunId,
            new SastExportSummary(Expected.Length, passed, failed, pending,
                scannerResults.Count(result => result.Method == "SAST-SARIF"),
                scannerResults.Count(result => result.CaseId == "SAST-UNMAPPED")),
            output.OrderBy(result => result.CaseId).ThenBy(result => result.TimestampUtc).ToList());
    }

    private static LabExecutionResult Pending(SastCase item, Guid testRunId)
    {
        var evidence = new Dictionary<string, string?>
        {
            ["case"] = item.Name,
            ["detected"] = "False",
            ["validationStatus"] = "pending",
            ["expectedDetection"] = item.ExpectedDetection.ToString(),
            ["expectedClassification"] = item.ExpectedDetection ? "true_positive" : "false_positive"
        };
        return new LabExecutionResult(
            Guid.NewGuid(), DateTimeOffset.UtcNow, item.CaseId, "SAST-PENDING",
            "src/AspmLab/Program.cs", item.Name,
            item.ExpectedDetection
                ? "Import SARIF and verify that the expected SAST weakness is present."
                : "Import SARIF and manually classify the token-shaped public identifier.",
            "No SARIF result has been imported for this case.", null, null,
            "Pending is not a failed test.", "SAST scanner", Severity: item.Severity,
            File: "src/AspmLab/Program.cs", Source: "sast", TestRunId: testRunId,
            Assertion: "Import scanner evidence before evaluating this case.", Evidence: evidence);
    }

    private sealed record SastCase(string CaseId, string Severity, string Name, bool ExpectedDetection);
}
