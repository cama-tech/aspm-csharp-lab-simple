public sealed record IacExportSummary(int ExpectedCases, int PassedCases, int FailedCases,
    int PendingCases, int ImportedFindings, int UnmappedFindings);

public sealed record IacExportReport(DateTimeOffset GeneratedAtUtc, Guid TestRunId,
    IacExportSummary Summary, IReadOnlyList<LabExecutionResult> Results)
{
    private static readonly IacCase[] Expected =
    {
        new("IAC-CRITICAL-001", "critical", true),
        new("IAC-HIGH-001", "high", true),
        new("IAC-MEDIUM-001", "medium", true),
        new("IAC-LOW-001", "low", true),
        new("IAC-FP-001", "informational", false)
    };

    public static IacExportReport Create(IReadOnlyList<LabExecutionResult> results, Guid testRunId)
    {
        var imported = results.Where(item => item.Method == "IAC-IMPORT").ToList();
        var output = imported.ToList();
        var passed = 0; var failed = 0; var pending = 0;
        foreach (var item in Expected)
        {
            var matches = imported.Where(result => result.CaseId == item.CaseId).ToList();
            if (matches.Any(result => result.Passed == false)) failed++;
            else if (matches.Any(result => result.Passed == true)) passed++;
            else { pending++; output.Add(Pending(item, testRunId)); }
        }
        return new IacExportReport(DateTimeOffset.UtcNow, testRunId,
            new IacExportSummary(Expected.Length, passed, failed, pending,
                imported.Count(item => item.Evidence?.GetValueOrDefault("detected") == "True"),
                imported.Count(item => item.CaseId == "IAC-UNMAPPED")),
            output.OrderBy(item => item.CaseId).ThenBy(item => item.TimestampUtc).ToList());
    }

    private static LabExecutionResult Pending(IacCase item, Guid testRunId) => new(
        Guid.NewGuid(), DateTimeOffset.UtcNow, item.CaseId, "IAC-PENDING", "infra/", string.Empty,
        "Import Checkov JSON and validate this controlled IaC case.",
        "No Checkov result has been imported for this case.", null, null,
        "Pending is not a failed test.", "Checkov", Severity: item.Severity,
        Source: "iac", TestRunId: testRunId,
        Assertion: "Import scanner evidence before evaluating this case.",
        Evidence: new Dictionary<string, string?>
        {
            ["validationStatus"] = "pending",
            ["expectedDetection"] = item.ExpectedDetection.ToString()
        });

    private sealed record IacCase(string CaseId, string Severity, bool ExpectedDetection);
}
