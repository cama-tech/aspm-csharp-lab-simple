using System.Globalization;
using System.Text.Json;

public static class SarifImporter
{
    public static async Task<SarifImportSummary> ImportAsync(Stream stream, LabResultStore store)
    {
        using var document = await JsonDocument.ParseAsync(stream);
        if (!document.RootElement.TryGetProperty("runs", out var runs) || runs.ValueKind != JsonValueKind.Array)
            throw new JsonException("The SARIF document does not contain a runs array.");

        var imported = 0;
        var mapped = 0;
        var unmapped = 0;

        foreach (var run in runs.EnumerateArray())
        {
            var driver = run.GetProperty("tool").GetProperty("driver");
            var tool = GetString(driver, "name") ?? "Unknown SARIF tool";
            var toolVersion = GetString(driver, "semanticVersion") ?? GetString(driver, "version");
            var rules = ReadRules(driver);

            if (!run.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
                continue;

            foreach (var result in results.EnumerateArray())
            {
                var ruleId = GetString(result, "ruleId") ?? "unknown-rule";
                var message = result.TryGetProperty("message", out var messageElement)
                    ? GetString(messageElement, "text") ?? GetString(messageElement, "markdown") ?? string.Empty
                    : string.Empty;
                var location = ReadLocation(result);
                rules.TryGetValue(ruleId, out var rule);
                var severity = ResolveSeverity(result, rule);
                var caseId = ResolveCaseId(ruleId, message);
                var isMapped = caseId != "SAST-UNMAPPED";
                if (isMapped) mapped++; else unmapped++;

                var controlledFalsePositive = caseId == "SAST-FP-001" &&
                    ruleId.EndsWith("aspm.sast.public-documentation-id", StringComparison.OrdinalIgnoreCase);
                var requiresReview = (caseId == "SAST-FP-001" && !controlledFalsePositive) || !isMapped;
                store.Add(new LabExecutionResult(
                    Guid.NewGuid(),
                    DateTimeOffset.UtcNow,
                    caseId,
                    "SAST-SARIF",
                    location.File ?? string.Empty,
                    ruleId,
                    ExpectedFor(caseId),
                    $"SARIF finding imported from {tool}",
                    requiresReview ? null : true,
                    null,
                    requiresReview
                        ? "Imported automatically; manual classification is required."
                        : "Imported and correlated automatically with an expected laboratory case.",
                    tool,
                    toolVersion,
                    ruleId,
                    severity,
                    location.File,
                    location.Line,
                    message,
                    "sarif",
                    TestRunId: store.TestRunId,
                    Assertion: requiresReview
                        ? "Review and classify the imported SAST finding."
                        : "The expected SAST weakness must be reported by the scanner.",
                    Evidence: new Dictionary<string, string?>
                    {
                        ["detected"] = "True",
                        ["ruleId"] = ruleId,
                        ["file"] = location.File,
                        ["line"] = location.Line?.ToString(),
                        ["expectedClassification"] = caseId == "SAST-FP-001" ? "false_positive" : "true_positive",
                        ["validationStatus"] = controlledFalsePositive ? "passed" : requiresReview ? "review_required" : "passed"
                    }));
                imported++;
            }
        }

        return new SarifImportSummary(imported, mapped, unmapped);
    }

    private static Dictionary<string, SarifRule> ReadRules(JsonElement driver)
    {
        var rules = new Dictionary<string, SarifRule>(StringComparer.OrdinalIgnoreCase);
        if (!driver.TryGetProperty("rules", out var ruleElements) || ruleElements.ValueKind != JsonValueKind.Array)
            return rules;

        foreach (var element in ruleElements.EnumerateArray())
        {
            var id = GetString(element, "id");
            if (string.IsNullOrWhiteSpace(id)) continue;
            string? securitySeverity = null;
            if (element.TryGetProperty("properties", out var properties))
                securitySeverity = GetString(properties, "security-severity");
            rules[id] = new SarifRule(securitySeverity);
        }
        return rules;
    }

    private static (string? File, int? Line) ReadLocation(JsonElement result)
    {
        if (!result.TryGetProperty("locations", out var locations) || locations.ValueKind != JsonValueKind.Array)
            return (null, null);
        var first = locations.EnumerateArray().FirstOrDefault();
        if (first.ValueKind == JsonValueKind.Undefined ||
            !first.TryGetProperty("physicalLocation", out var physical))
            return (null, null);

        string? file = null;
        int? line = null;
        if (physical.TryGetProperty("artifactLocation", out var artifact))
            file = GetString(artifact, "uri");
        if (physical.TryGetProperty("region", out var region) &&
            region.TryGetProperty("startLine", out var startLine) && startLine.TryGetInt32(out var parsedLine))
            line = parsedLine;
        return (file, line);
    }

    private static string ResolveSeverity(JsonElement result, SarifRule? rule)
    {
        if (rule?.SecuritySeverity is { } scoreText &&
            double.TryParse(scoreText, NumberStyles.Float, CultureInfo.InvariantCulture, out var score))
        {
            if (score >= 9) return "critical";
            if (score >= 7) return "high";
            if (score >= 4) return "medium";
            return "low";
        }

        return (GetString(result, "level") ?? "unknown").ToLowerInvariant() switch
        {
            "error" => "high",
            "warning" => "medium",
            "note" => "low",
            "none" => "informational",
            var level => level
        };
    }

    private static string ResolveCaseId(string ruleId, string message)
    {
        var text = $"{ruleId} {message}".ToLowerInvariant();
        if (ContainsAny(text, "command injection", "os command", "processstartinfo", "process execution")) return "NEW-SAST-001";
        if (ContainsAny(text, "cross-site scripting", "cross site scripting", "xss", "output encoding", "html encoding")) return "BASELINE-SAST-001";
        if (ContainsAny(text, "open redirect", "unvalidated redirect", "url redirection")) return "BASELINE-SAST-002";
        if (ContainsAny(text, "path traversal", "path injection", "user controlled path")) return "BASELINE-SAST-003";
        if (ContainsAny(text, "sensitive information", "sensitive data", "cleartext logging", "log injection")) return "MEDIUM-SAST-001";
        if (ContainsAny(text, "deserialization", "typenamehandling", "unsafe type")) return "LOW-SAST-001";
        if (ContainsAny(text, "hardcoded secret", "hard-coded secret", "credential", "github token")) return "SAST-FP-001";
        return "SAST-UNMAPPED";
    }

    private static string ExpectedFor(string caseId) => caseId switch
    {
        "NEW-SAST-001" => "The scanner identifies controlled OS command execution through ProcessStartInfo.",
        "BASELINE-SAST-001" => "The scanner identifies reflected input without HTML output encoding.",
        "BASELINE-SAST-002" => "The scanner identifies an externally controlled redirect.",
        "BASELINE-SAST-003" => "The scanner identifies a user-controlled file path.",
        "MEDIUM-SAST-001" => "The scanner identifies sensitive information written to logs.",
        "LOW-SAST-001" => "The scanner identifies unsafe deserialization with TypeNameHandling.All.",
        "SAST-FP-001" => "The scanner result must be manually confirmed as a false positive.",
        _ => "Review and correlate this finding manually."
    };

    private static bool ContainsAny(string text, params string[] values) =>
        values.Any(value => text.Contains(value, StringComparison.OrdinalIgnoreCase));

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private sealed record SarifRule(string? SecuritySeverity);
}

public record SarifImportSummary(int Imported, int Mapped, int Unmapped);
