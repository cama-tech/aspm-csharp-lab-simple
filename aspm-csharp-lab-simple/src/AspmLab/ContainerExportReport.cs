public sealed record ContainerExportSummary(int ExpectedCases, int PassedCases, int FailedCases,
    int PendingCases, int ImportedFindings, int UnmappedFindings);

public sealed record ContainerExportReport(DateTimeOffset GeneratedAtUtc, Guid TestRunId,
    ContainerExportSummary Summary, IReadOnlyList<LabExecutionResult> Results)
{
    private static readonly ContainerCase[] Expected =
    {
        new("CONTAINER-CRITICAL-001", "critical", true),
        new("CONTAINER-HIGH-001", "high", true),
        new("CONTAINER-HIGH-002", "high", true),
        new("CONTAINER-MEDIUM-001", "medium", true),
        new("CONTAINER-LOW-001", "low", true),
        new("CONTAINER-LOW-002", "low", true),
        new("CONTAINER-FP-001", "informational", false)
    };

    public static ContainerExportReport Create(IReadOnlyList<LabExecutionResult> results, Guid testRunId)
    {
        var imported = results.Where(item => item.Method == "CONTAINER-IMPORT").ToList();
        var output = imported.ToList();
        var passed = 0; var failed = 0; var pending = 0;
        foreach (var item in Expected)
        {
            var matches = imported.Where(result => result.CaseId == item.CaseId).ToList();
            if (matches.Any(result => result.Passed == false)) failed++;
            else if (matches.Any(result => result.Passed == true)) passed++;
            else if (!item.ExpectedDetection && ConfigScanWasImported(imported))
            {
                passed++;
                output.Add(NegativeControlPassed(item, testRunId));
            }
            else { pending++; output.Add(Pending(item, testRunId)); }
        }
        return new ContainerExportReport(DateTimeOffset.UtcNow, testRunId,
            new ContainerExportSummary(Expected.Length, passed, failed, pending,
                imported.Count(item => item.Evidence?.GetValueOrDefault("detected") == "True"),
                imported.Count(item => item.CaseId == "CONTAINER-UNMAPPED")),
            output.OrderBy(item => item.CaseId).ThenBy(item => item.TimestampUtc).ToList());
    }

    private static bool ConfigScanWasImported(IReadOnlyList<LabExecutionResult> imported) =>
        imported.Any(item => item.Evidence?.GetValueOrDefault("findingType") == "misconfiguration");

    private static LabExecutionResult NegativeControlPassed(ContainerCase item, Guid testRunId) => new(
        Guid.NewGuid(), DateTimeOffset.UtcNow, item.CaseId, "CONTAINER-VALIDATION", "docker-compose.yml",
        "127.0.0.1:8080:8080", "The localhost binding must not be classified as public exposure.",
        "The Trivy configuration scan completed without reporting the localhost binding as public exposure.",
        true, null, "Controlled container negative case.", "Trivy", Severity: item.Severity,
        File: "docker-compose.yml", Source: "container", TestRunId: testRunId,
        Assertion: "127.0.0.1 is distinguished from 0.0.0.0.",
        Evidence: new Dictionary<string, string?>
        {
            ["detected"] = "False", ["expectedDetection"] = "False",
            ["binding"] = "127.0.0.1:8080:8080", ["validationStatus"] = "passed"
        });

    private static LabExecutionResult Pending(ContainerCase item, Guid testRunId) => new(
        Guid.NewGuid(), DateTimeOffset.UtcNow, item.CaseId, "CONTAINER-PENDING", "Dockerfile", string.Empty,
        "Import Trivy image/config JSON and validate this controlled container case.",
        "No Trivy result has been imported for this case.", null, null,
        "Pending is not a failed test.", "Trivy", Severity: item.Severity,
        Source: "container", TestRunId: testRunId,
        Assertion: "Import scanner evidence before evaluating this case.",
        Evidence: new Dictionary<string, string?>
        {
            ["validationStatus"] = "pending", ["expectedDetection"] = item.ExpectedDetection.ToString()
        });

    private sealed record ContainerCase(string CaseId, string Severity, bool ExpectedDetection);
}
