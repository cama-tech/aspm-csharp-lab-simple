public sealed record ScaExportSummary(
    int ExpectedCases,
    int PassedCases,
    int FailedCases,
    int PendingCases,
    int ImportedFindings,
    int UnmappedFindings);

public sealed record ScaExportReport(
    DateTimeOffset GeneratedAtUtc,
    Guid TestRunId,
    ScaExportSummary Summary,
    IReadOnlyList<LabExecutionResult> Results)
{
    private static readonly ExpectedScaExportCase[] ExpectedCases =
    {
        new("SCA-CRITICAL-001", "DNS", "6.1.0", "critical", 1, true),
        new("SCA-CRITICAL-002", "System.Text.Encodings.Web", "4.7.0", "critical", 1, true),
        new("SCA-HIGH-001", "Newtonsoft.Json", "12.0.1", "high", 1),
        new("SCA-MULTI-001", "SixLabors.ImageSharp", "2.1.3", "moderate", 2, true),
        new("SCA-LOW-001", "EnumStringValues", "4.0.0", "low", 1, true),
        new("SCA-FP-001", "Fake.Vulnerable.Package", "1.0.0", "none", 0, false)
    };

    public static ScaExportReport Create(IReadOnlyList<LabExecutionResult> results, Guid testRunId)
    {
        var exportedResults = results.ToList();
        var passed = 0;
        var failed = 0;
        var pending = 0;
        foreach (var expectedCase in ExpectedCases)
        {
            var caseResults = results.Where(result => result.CaseId == expectedCase.CaseId).ToList();
            if (caseResults.Any(result => result.Passed == false)) failed++;
            else if (caseResults.Any(result => result.Passed == true)) passed++;
            else
            {
                pending++;
                exportedResults.Add(CreatePendingResult(expectedCase, testRunId));
            }
        }

        var summary = new ScaExportSummary(
            ExpectedCases.Length,
            passed,
            failed,
            pending,
            results.Count(result => result.Method == "SCA-IMPORT"),
            results.Count(result => result.CaseId == "SCA-UNMAPPED"));
        return new ScaExportReport(
            DateTimeOffset.UtcNow,
            testRunId,
            summary,
            exportedResults.OrderBy(result => result.CaseId).ThenBy(result => result.TimestampUtc).ToList());
    }

    private static LabExecutionResult CreatePendingResult(ExpectedScaExportCase item, Guid testRunId)
    {
        var now = DateTimeOffset.UtcNow;
        var evidence = new Dictionary<string, string?>
        {
            ["package"] = item.Package,
            ["expectedVersion"] = item.Version,
            ["expectedSeverity"] = item.Severity,
            ["minimumExpectedFindings"] = item.MinimumFindings.ToString(),
            ["detectedFindings"] = "0",
            ["detected"] = "False",
            ["validationStatus"] = "pending",
            ["expectedDetection"] = item.ExpectedDetection.ToString(),
            ["project"] = "src/AspmLab/AspmLab.csproj"
        };

        return new LabExecutionResult(
            Guid.NewGuid(),
            now,
            item.CaseId,
            "SCA-PENDING",
            "src/AspmLab/AspmLab.csproj",
            $"{item.Package} {item.Version}",
            $"Detect at least {item.MinimumFindings} vulnerability finding(s) for {item.Package} {item.Version}.",
            "No SCA result has been imported for this expected case.",
            null,
            null,
            "Expected SCA case exported as pending; this is not a failed test.",
            "dotnet list package",
            null,
            null,
            item.Severity,
            "src/AspmLab/AspmLab.csproj",
            null,
            $"Pending SCA validation for {item.Package} {item.Version}.",
            "sca",
            TestRunId: testRunId,
            StartedAtUtc: null,
            CompletedAtUtc: null,
            Assertion: "Import the SCA scanner output and verify the expected package, version and findings.",
            FailureReason: null,
            Evidence: evidence);
    }

    private sealed record ExpectedScaExportCase(
        string CaseId,
        string Package,
        string Version,
        string Severity,
        int MinimumFindings,
        bool ExpectedDetection = true);
}
