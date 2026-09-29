using System.Text.Json;

public sealed record ContainerImportSummary(int ResultsScanned, int Imported, int Mapped, int Unmapped);

public static class ContainerImporter
{
    public static async Task<ContainerImportSummary> ImportAsync(Stream stream, LabResultStore store)
    {
        using var document = await JsonDocument.ParseAsync(stream);
        var root = document.RootElement;
        if (!root.TryGetProperty("Results", out var resultsNode) || resultsNode.ValueKind != JsonValueKind.Array)
            throw new JsonException("Trivy Results array is required.");

        var imported = 0; var mapped = 0; var unmapped = 0;
        var composeWasScanned = false;
        var composeReportedPublic = false;
        foreach (var result in resultsNode.EnumerateArray())
        {
            var target = Text(result, "Target") ?? "unknown";
            if (target.EndsWith("docker-compose.yml", StringComparison.OrdinalIgnoreCase)) composeWasScanned = true;

            if (result.TryGetProperty("Vulnerabilities", out var vulnerabilities) && vulnerabilities.ValueKind == JsonValueKind.Array)
            {
                foreach (var vulnerability in vulnerabilities.EnumerateArray())
                {
                    var caseId = PackageCase(Text(vulnerability, "PkgName"), Text(vulnerability, "Severity"));
                    store.Add(VulnerabilityResult(store, target, vulnerability, caseId));
                    imported++;
                    if (caseId == "CONTAINER-UNMAPPED") unmapped++; else mapped++;
                }
            }

            if (result.TryGetProperty("Misconfigurations", out var misconfigurations) && misconfigurations.ValueKind == JsonValueKind.Array)
            {
                foreach (var misconfiguration in misconfigurations.EnumerateArray())
                {
                    var raw = misconfiguration.GetRawText();
                    var caseId = MisconfigurationCase(raw);
                    if (target.EndsWith("docker-compose.yml", StringComparison.OrdinalIgnoreCase) &&
                        LooksLikePublicExposure(raw)) composeReportedPublic = true;
                    store.Add(MisconfigurationResult(store, target, misconfiguration, caseId));
                    imported++;
                    if (caseId == "CONTAINER-UNMAPPED") unmapped++; else mapped++;
                }
            }
        }

        if (composeWasScanned)
        {
            store.Add(FalsePositiveResult(store, composeReportedPublic));
            imported++; mapped++;
        }
        return new ContainerImportSummary(resultsNode.GetArrayLength(), imported, mapped, unmapped);
    }

    private static string PackageCase(string? package, string? severity)
    {
        if ((package?.Equals("DNS", StringComparison.OrdinalIgnoreCase) == true ||
             package?.Equals("System.Text.Encodings.Web", StringComparison.OrdinalIgnoreCase) == true) &&
            severity?.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase) == true)
            return "CONTAINER-CRITICAL-001";
        if (package?.Equals("Newtonsoft.Json", StringComparison.OrdinalIgnoreCase) == true &&
            severity?.Equals("HIGH", StringComparison.OrdinalIgnoreCase) == true)
            return "CONTAINER-HIGH-002";
        if (package?.Equals("SixLabors.ImageSharp", StringComparison.OrdinalIgnoreCase) == true &&
            severity?.Equals("MEDIUM", StringComparison.OrdinalIgnoreCase) == true)
            return "CONTAINER-MEDIUM-001";
        if (package?.Equals("EnumStringValues", StringComparison.OrdinalIgnoreCase) == true &&
            severity?.Equals("LOW", StringComparison.OrdinalIgnoreCase) == true)
            return "CONTAINER-LOW-002";
        return "CONTAINER-UNMAPPED";
    }

    private static string MisconfigurationCase(string raw)
    {
        if (raw.Contains("healthcheck", StringComparison.OrdinalIgnoreCase)) return "CONTAINER-LOW-001";
        if (raw.Contains("non-root", StringComparison.OrdinalIgnoreCase) ||
            raw.Contains("root user", StringComparison.OrdinalIgnoreCase) ||
            raw.Contains("last user", StringComparison.OrdinalIgnoreCase)) return "CONTAINER-HIGH-001";
        return "CONTAINER-UNMAPPED";
    }

    private static LabExecutionResult VulnerabilityResult(LabResultStore store, string target,
        JsonElement item, string caseId)
    {
        var vulnerabilityId = Text(item, "VulnerabilityID");
        var package = Text(item, "PkgName");
        var installed = Text(item, "InstalledVersion");
        var fixedVersion = Text(item, "FixedVersion");
        var severity = Text(item, "Severity")?.ToLowerInvariant();
        var evidence = new Dictionary<string, string?>
        {
            ["detected"] = "True", ["findingType"] = "vulnerability", ["target"] = target,
            ["package"] = package, ["installedVersion"] = installed, ["fixedVersion"] = fixedVersion,
            ["vulnerabilityId"] = vulnerabilityId, ["observedSeverity"] = severity
        };
        return new LabExecutionResult(Guid.NewGuid(), DateTimeOffset.UtcNow, caseId, "CONTAINER-IMPORT",
            target, $"{package} {installed}", "Detect the controlled vulnerable component in the image.",
            $"Trivy found {vulnerabilityId} in {package} {installed}.", caseId == "CONTAINER-UNMAPPED" ? null : true,
            null, caseId == "CONTAINER-UNMAPPED" ? "Additional container finding requires review." : "Mapped image vulnerability.",
            "Trivy", RuleId: vulnerabilityId, Severity: severity, File: target,
            Message: Text(item, "Title"), Source: "container", TestRunId: store.TestRunId,
            Assertion: "The package, installed version, vulnerability and severity are retained.", Evidence: evidence);
    }

    private static LabExecutionResult MisconfigurationResult(LabResultStore store, string target,
        JsonElement item, string caseId)
    {
        var ruleId = Text(item, "ID") ?? Text(item, "AVDID");
        var title = Text(item, "Title");
        var severity = Text(item, "Severity")?.ToLowerInvariant();
        var line = StartLine(item);
        var evidence = new Dictionary<string, string?>
        {
            ["detected"] = "True", ["findingType"] = "misconfiguration", ["target"] = target,
            ["ruleId"] = ruleId, ["startLine"] = line?.ToString(), ["observedSeverity"] = severity
        };
        return new LabExecutionResult(Guid.NewGuid(), DateTimeOffset.UtcNow, caseId, "CONTAINER-IMPORT",
            target, title ?? string.Empty, "Detect the controlled container misconfiguration.",
            $"Trivy reported {ruleId}: {title}.", caseId == "CONTAINER-UNMAPPED" ? null : true,
            null, caseId == "CONTAINER-UNMAPPED" ? "Additional container finding requires review." : "Mapped container configuration finding.",
            "Trivy", RuleId: ruleId, Severity: severity, File: target, Line: line,
            Message: Text(item, "Message") ?? title, Source: "container", TestRunId: store.TestRunId,
            Assertion: "The Trivy rule, target, line and message are retained.", Evidence: evidence);
    }

    private static LabExecutionResult FalsePositiveResult(LabResultStore store, bool incorrectlyReported) => new(
        Guid.NewGuid(), DateTimeOffset.UtcNow, "CONTAINER-FP-001", "CONTAINER-IMPORT", "docker-compose.yml",
        "127.0.0.1:8080:8080", "The localhost binding must not be classified as public exposure.",
        incorrectlyReported ? "Trivy classified the localhost binding as public exposure." : "No public-exposure finding was reported for the localhost binding.",
        !incorrectlyReported, null, "Controlled container negative case.", "Trivy", Severity: "informational",
        File: "docker-compose.yml", Source: "container", TestRunId: store.TestRunId,
        Assertion: "127.0.0.1 is distinguished from 0.0.0.0.",
        FailureReason: incorrectlyReported ? "The local-only binding was treated as publicly exposed." : null,
        Evidence: new Dictionary<string, string?>
        {
            ["detected"] = incorrectlyReported.ToString(), ["expectedDetection"] = "False",
            ["binding"] = "127.0.0.1:8080:8080", ["validationStatus"] = incorrectlyReported ? "failed" : "passed"
        });

    private static bool LooksLikePublicExposure(string raw) =>
        raw.Contains("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
        raw.Contains("public exposure", StringComparison.OrdinalIgnoreCase) ||
        raw.Contains("all interfaces", StringComparison.OrdinalIgnoreCase);

    private static int? StartLine(JsonElement item)
    {
        if (!item.TryGetProperty("CauseMetadata", out var metadata) ||
            !metadata.TryGetProperty("StartLine", out var line) || line.ValueKind != JsonValueKind.Number) return null;
        return line.GetInt32();
    }

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
