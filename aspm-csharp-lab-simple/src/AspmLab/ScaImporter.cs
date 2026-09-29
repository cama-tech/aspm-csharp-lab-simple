using System.Text.Json;

public static class ScaImporter
{
    public static async Task<ScaImportSummary> ImportAsync(Stream stream, LabResultStore store)
    {
        using var document = await JsonDocument.ParseAsync(stream);
        if (!document.RootElement.TryGetProperty("projects", out var projects) ||
            projects.ValueKind != JsonValueKind.Array)
            throw new JsonException("The SCA document does not contain a projects array.");

        var projectsScanned = 0;
        var packagesScanned = 0;
        var imported = 0;
        var mapped = 0;
        var unmapped = 0;
        var validatesLaboratoryFixture = false;

        foreach (var project in projects.EnumerateArray())
        {
            projectsScanned++;
            var projectPath = ReadString(project, "path") ?? "unknown-project";
            if (projectPath.EndsWith("AspmLab.csproj", StringComparison.OrdinalIgnoreCase))
                validatesLaboratoryFixture = true;
            if (!project.TryGetProperty("frameworks", out var frameworks) ||
                frameworks.ValueKind != JsonValueKind.Array)
                continue;

            foreach (var framework in frameworks.EnumerateArray())
            {
                var frameworkName = ReadString(framework, "framework");
                foreach (var collectionName in new[] { "topLevelPackages", "transitivePackages" })
                {
                    if (!framework.TryGetProperty(collectionName, out var packages) ||
                        packages.ValueKind != JsonValueKind.Array)
                        continue;

                    var dependencyType = collectionName == "topLevelPackages" ? "direct" : "transitive";
                    foreach (var package in packages.EnumerateArray())
                    {
                        packagesScanned++;
                        ImportPackage(
                            package,
                            projectPath,
                            frameworkName,
                            dependencyType,
                            store,
                            ref imported,
                            ref mapped,
                            ref unmapped);
                    }
                }
            }
        }

        if (validatesLaboratoryFixture)
            AddMissingExpectedResults(store);

        return new ScaImportSummary(projectsScanned, packagesScanned, imported, mapped, unmapped);
    }

    private static void ImportPackage(
        JsonElement package,
        string projectPath,
        string? framework,
        string dependencyType,
        LabResultStore store,
        ref int imported,
        ref int mapped,
        ref int unmapped)
    {
        var packageId = ReadString(package, "id") ?? "unknown-package";
        var requestedVersion = ReadString(package, "requestedVersion");
        var resolvedVersion = ReadString(package, "resolvedVersion") ?? requestedVersion ?? "unknown-version";
        if (!package.TryGetProperty("vulnerabilities", out var vulnerabilities) ||
            vulnerabilities.ValueKind != JsonValueKind.Array)
            return;

        foreach (var vulnerability in vulnerabilities.EnumerateArray())
        {
            var severity = (ReadString(vulnerability, "severity") ?? "unknown").ToLowerInvariant();
            var advisoryUrl = ReadString(vulnerability, "advisoryurl") ??
                              ReadString(vulnerability, "advisoryUrl") ??
                              "unknown-advisory";
            var caseId = ResolveCaseId(packageId);
            var isMapped = caseId != "SCA-UNMAPPED";
            var expectedVersion = ExpectedVersion(caseId);
            var versionMatches = expectedVersion is null || resolvedVersion == expectedVersion;
            var expectedSeverity = ExpectedSeverity(caseId);
            var severityMatches = expectedSeverity is null || severity == expectedSeverity;
            var unexpectedFalsePositive = caseId == "SCA-FP-001";
            if (isMapped) mapped++; else unmapped++;

            var evidence = new Dictionary<string, string?>
            {
                ["package"] = packageId,
                ["requestedVersion"] = requestedVersion,
                ["resolvedVersion"] = resolvedVersion,
                ["dependencyType"] = dependencyType,
                ["framework"] = framework,
                ["advisoryUrl"] = advisoryUrl,
                ["expectedVersion"] = expectedVersion,
                ["versionMatches"] = versionMatches.ToString(),
                ["expectedSeverity"] = expectedSeverity,
                ["severityMatches"] = severityMatches.ToString(),
                ["detected"] = "True"
            };

            store.Add(new LabExecutionResult(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                caseId,
                "SCA-IMPORT",
                projectPath,
                $"{packageId} {resolvedVersion}",
                ExpectedFor(caseId, packageId, resolvedVersion),
                $"Vulnerability reported for {packageId} {resolvedVersion}",
                isMapped ? unexpectedFalsePositive ? false : versionMatches : null,
                null,
                unexpectedFalsePositive
                    ? "The scanner reported the false-positive control as an installed vulnerable package."
                    : isMapped && versionMatches
                    ? severityMatches
                        ? "Imported and matched the expected SCA case, version and severity."
                        : "Imported and matched the expected package and version; the scanner reported a different severity."
                    : "Imported but not correlated; manual review is required.",
                "dotnet list package",
                null,
                advisoryUrl,
                severity,
                projectPath,
                null,
                $"{packageId} {resolvedVersion}: {advisoryUrl}",
                "sca",
                TestRunId: store.TestRunId,
                Assertion: "The SCA tool must report a vulnerability for the expected package and version.",
                FailureReason: unexpectedFalsePositive
                    ? "A documentation-only package name was reported as a real dependency."
                    : isMapped && !versionMatches
                        ? $"Expected version {expectedVersion}, but the scanner reported {resolvedVersion}."
                        : null,
                Evidence: evidence));
            imported++;
        }
    }

    private static string ResolveCaseId(string packageId) => packageId.ToLowerInvariant() switch
    {
        "dns" => "SCA-CRITICAL-001",
        "system.text.encodings.web" => "SCA-CRITICAL-002",
        "newtonsoft.json" => "SCA-HIGH-001",
        "sixlabors.imagesharp" => "SCA-MULTI-001",
        "enumstringvalues" => "SCA-LOW-001",
        "fake.vulnerable.package" => "SCA-FP-001",
        _ => "SCA-UNMAPPED"
    };

    private static string? ExpectedVersion(string caseId) => caseId switch
    {
        "SCA-CRITICAL-001" => "6.1.0",
        "SCA-CRITICAL-002" => "4.7.0",
        "SCA-HIGH-001" => "12.0.1",
        "SCA-MULTI-001" => "2.1.3",
        "SCA-LOW-001" => "4.0.0",
        "SCA-FP-001" => "1.0.0",
        _ => null
    };

    private static string? ExpectedSeverity(string caseId) => caseId switch
    {
        "SCA-CRITICAL-001" => "critical",
        "SCA-CRITICAL-002" => "critical",
        "SCA-HIGH-001" => "high",
        "SCA-MULTI-001" => "moderate",
        "SCA-LOW-001" => "low",
        _ => null
    };

    private static void AddMissingExpectedResults(LabResultStore store)
    {
        var results = store.GetSca();
        var expected = new[]
        {
            new ExpectedScaCase("SCA-CRITICAL-001", "DNS", "6.1.0", 1, true),
            new ExpectedScaCase("SCA-CRITICAL-002", "System.Text.Encodings.Web", "4.7.0", 1, true),
            new ExpectedScaCase("SCA-HIGH-001", "Newtonsoft.Json", "12.0.1", 1, true),
            new ExpectedScaCase("SCA-MULTI-001", "SixLabors.ImageSharp", "2.1.3", 2, true),
            new ExpectedScaCase("SCA-LOW-001", "EnumStringValues", "4.0.0", 1, true),
            new ExpectedScaCase("SCA-FP-001", "Fake.Vulnerable.Package", "1.0.0", 0, false)
        };

        foreach (var item in expected)
        {
            var detected = results.Count(result =>
                result.CaseId == item.CaseId &&
                result.Evidence is not null &&
                result.Evidence.TryGetValue("resolvedVersion", out var version) &&
                version == item.Version);
            if (item.ExpectedDetection && detected >= item.MinimumFindings) continue;
            if (!item.ExpectedDetection && detected == 0)
            {
                store.Add(CreateNegativeScaResult(store, item));
                continue;
            }

            var evidence = new Dictionary<string, string?>
            {
                ["package"] = item.Package,
                ["expectedVersion"] = item.Version,
                ["detectedFindings"] = detected.ToString(),
                ["minimumExpectedFindings"] = item.MinimumFindings.ToString(),
                ["detected"] = "False"
            };
            store.Add(new LabExecutionResult(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                item.CaseId,
                "SCA-VALIDATION",
                "src/AspmLab/AspmLab.csproj",
                $"{item.Package} {item.Version}",
                $"Detect at least {item.MinimumFindings} vulnerability finding(s) for {item.Package} {item.Version}.",
                $"Detected {detected} of {item.MinimumFindings} expected finding(s).",
                false,
                null,
                "Automatically generated because the expected SCA result was missing or incomplete.",
                "dotnet list package",
                null,
                null,
                null,
                "src/AspmLab/AspmLab.csproj",
                null,
                $"Expected SCA result not fully detected for {item.Package} {item.Version}.",
                "sca",
                TestRunId: store.TestRunId,
                Assertion: "The expected dependency vulnerability must be present in the imported SCA results.",
                FailureReason: $"Only {detected} of {item.MinimumFindings} expected finding(s) were detected.",
                Evidence: evidence));
        }
    }

    private static LabExecutionResult CreateNegativeScaResult(LabResultStore store, ExpectedScaCase item)
    {
        var evidence = new Dictionary<string, string?>
        {
            ["package"] = item.Package,
            ["expectedVersion"] = item.Version,
            ["expectedDetection"] = "False",
            ["detectedFindings"] = "0",
            ["detected"] = "False",
            ["classification"] = "false_positive_control"
        };
        return new LabExecutionResult(
            Guid.NewGuid(), DateTimeOffset.UtcNow, item.CaseId, "SCA-VALIDATION",
            "src/AspmLab/AspmLab.csproj", $"{item.Package} {item.Version}",
            "Do not report the documentation-only package name as an installed dependency.",
            "No dependency vulnerability was reported for the false-positive control.",
            true, null, "The negative SCA control behaved as expected.",
            "dotnet list package", Source: "sca", TestRunId: store.TestRunId,
            Assertion: "Text resembling a package declaration must not be treated as an installed component.",
            Evidence: evidence);
    }

    private static string ExpectedFor(string caseId, string packageId, string version) => caseId switch
    {
        "SCA-CRITICAL-001" => "Detect vulnerabilities applicable to DNS 6.1.0.",
        "SCA-CRITICAL-002" => "Detect vulnerabilities applicable to System.Text.Encodings.Web 4.7.0.",
        "SCA-HIGH-001" => "Detect vulnerabilities applicable to Newtonsoft.Json 12.0.1.",
        "SCA-MULTI-001" => "Preserve every vulnerability applicable to SixLabors.ImageSharp 2.1.3.",
        "SCA-LOW-001" => "Detect vulnerabilities applicable to EnumStringValues 4.0.0.",
        "SCA-FP-001" => "Do not report a package name that exists only as documentation text.",
        _ => $"Review the SCA finding for {packageId} {version}."
    };

    private static string? ReadString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private sealed record ExpectedScaCase(
        string CaseId,
        string Package,
        string Version,
        int MinimumFindings,
        bool ExpectedDetection);
}

public record ScaImportSummary(
    int ProjectsScanned,
    int PackagesScanned,
    int Imported,
    int Mapped,
    int Unmapped);
