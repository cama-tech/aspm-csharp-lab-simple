public sealed record SbomExportSummary(int ExpectedCases, int PassedCases, int FailedCases,
    int PendingCases, int ImportedComponents, int AdditionalComponents);

public sealed record SbomExportReport(DateTimeOffset GeneratedAtUtc, Guid TestRunId,
    SbomExportSummary Summary, IReadOnlyList<LabExecutionResult> Results)
{
    private static readonly string[] Expected =
    {
        "SBOM-APP-001", "SBOM-DIRECT-001", "SBOM-DIRECT-002", "SBOM-DIRECT-003",
        "SBOM-DIRECT-004", "SBOM-DIRECT-005", "SBOM-TRANSITIVE-001",
        "SBOM-LICENSE-001", "SBOM-FP-001"
    };

    public static SbomExportReport Create(IReadOnlyList<LabExecutionResult> results, Guid testRunId)
    {
        var imported = results.Where(item => item.Method == "SBOM-IMPORT").ToList();
        var output = imported.ToList();
        var passed = 0; var failed = 0; var pending = 0;
        foreach (var caseId in Expected)
        {
            var matches = imported.Where(item => item.CaseId == caseId).ToList();
            if (matches.Any(item => item.Passed == false)) failed++;
            else if (matches.Any(item => item.Passed == true)) passed++;
            else { pending++; output.Add(Pending(caseId, testRunId)); }
        }
        return new SbomExportReport(DateTimeOffset.UtcNow, testRunId,
            new SbomExportSummary(Expected.Length, passed, failed, pending,
                imported.Count(item => item.Evidence?.GetValueOrDefault("kind") is "application" or "component"),
                imported.Count(item => item.CaseId == "SBOM-UNMAPPED")),
            output.OrderBy(item => item.CaseId).ThenBy(item => item.TimestampUtc).ToList());
    }

    private static LabExecutionResult Pending(string caseId, Guid testRunId) => new(
        Guid.NewGuid(), DateTimeOffset.UtcNow, caseId, "SBOM-PENDING", "bom.json", string.Empty,
        "Import a CycloneDX SBOM and validate this inventory case.",
        "No CycloneDX result has been imported for this case.", null, null,
        "Pending is not a failed test.", "CycloneDX", Severity: "informational", Source: "sbom",
        TestRunId: testRunId, Assertion: "Import SBOM evidence before evaluating this case.",
        Evidence: new Dictionary<string, string?> { ["validationStatus"] = "pending" });
}
