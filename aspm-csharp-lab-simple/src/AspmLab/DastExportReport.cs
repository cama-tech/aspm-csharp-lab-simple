public sealed record DastExportSummary(int ExpectedCases, int PassedCases, int FailedCases,
    int PendingCases, int ImportedFindings, int UnmappedFindings);

public sealed record DastExportReport(DateTimeOffset GeneratedAtUtc, Guid TestRunId,
    DastExportSummary Summary, IReadOnlyList<LabExecutionResult> Results)
{
    private static readonly DastCase[] Expected =
    {
        new("DAST-CRITICAL-001", "critical", false),
        new("DAST-HIGH-001", "high", true),
        new("DAST-HIGH-002", "high", true),
        new("DAST-MEDIUM-001", "medium", true),
        new("DAST-LOW-001", "low", true),
        new("DAST-FP-001", "informational", false)
    };

    public static DastExportReport Create(IReadOnlyList<LabExecutionResult> results, Guid testRunId)
    {
        var imported = results.Where(item => item.Method == "DAST-IMPORT").ToList();
        var validations = results.Where(item => item.Method == "DAST-CONTROL").ToList();
        var output = imported.Concat(validations).ToList();
        var passed = 0; var failed = 0; var pending = 0;
        foreach (var item in Expected)
        {
            var matches = output.Where(result => result.CaseId == item.CaseId).ToList();

            if (item.CaseId == "DAST-FP-001" &&
                !item.ExpectedDetection &&
                imported.Count > 0 &&
                matches.Count == 0)
            {
                passed++;
                output.Add(FalsePositivePassed(item, testRunId));
            }
            else if (matches.Any(result => result.Passed == false))
            {
                failed++;
            }
            else if (matches.Any(result => result.Passed == true))
            {
                passed++;
            }
            else
            {
                pending++;
                output.Add(Pending(item, testRunId));
            }
        }
        return new DastExportReport(DateTimeOffset.UtcNow, testRunId,
            new DastExportSummary(Expected.Length, passed, failed, pending,
                imported.Count(item => item.Evidence?.GetValueOrDefault("detected") == "True"),
                imported.Count(item => item.CaseId == "DAST-UNMAPPED")),
            output.OrderBy(item => item.CaseId).ThenBy(item => item.TimestampUtc).ToList());
    }

    private static LabExecutionResult FalsePositivePassed(DastCase item, Guid testRunId) => new(
    Guid.NewGuid(),
    DateTimeOffset.UtcNow,
    item.CaseId,
    "DAST-VALIDATION",
    "zap-results.json",
    string.Empty,
    "The controlled false-positive case must not be detected by OWASP ZAP.",
    "OWASP ZAP results were imported and no finding was mapped to this controlled false-positive case.",
    true,
    null,
    "Controlled false-positive validation.",
    "OWASP ZAP",
    Severity: item.Severity,
    Source: "dast",
    TestRunId: testRunId,
    Assertion: "The controlled false-positive case is not reported by the scanner.",
    Evidence: new Dictionary<string, string?>
    {
        ["validationStatus"] = "passed",
        ["expectedDetection"] = "False",
        ["actualDetection"] = "False",
        ["manualValidationRequired"] = "False"
    });

    private static LabExecutionResult Pending(DastCase item, Guid testRunId) => new(
        Guid.NewGuid(), DateTimeOffset.UtcNow, item.CaseId, "DAST-PENDING", "zap-results.json", string.Empty,
        item.CaseId == "DAST-CRITICAL-001"
            ? "Validate allowed commands and prove that arbitrary command syntax is rejected."
            : "Import OWASP ZAP JSON and validate this controlled DAST case.",
        item.CaseId == "DAST-CRITICAL-001"
            ? "No functional control result has been recorded for this case."
            : "No OWASP ZAP result has been imported for this case.", null, null,
        "Pending is not a failed test.", "OWASP ZAP", Severity: item.Severity,
        Source: "dast", TestRunId: testRunId,
        Assertion: "Import scanner evidence before evaluating this case.",
        Evidence: new Dictionary<string, string?>
        {
            ["validationStatus"] = "pending", ["expectedDetection"] = item.ExpectedDetection.ToString(),
            ["manualValidationRequired"] = (item.CaseId == "DAST-CRITICAL-001").ToString()
        });

    private sealed record DastCase(string CaseId, string Severity, bool ExpectedDetection);
}
