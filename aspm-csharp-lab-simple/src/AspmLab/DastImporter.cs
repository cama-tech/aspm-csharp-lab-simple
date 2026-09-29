using System.Text.Json;

public sealed record DastImportSummary(int AlertsScanned, int InstancesImported, int Mapped, int Unmapped);

public static class DastImporter
{
    public static async Task<DastImportSummary> ImportAsync(Stream stream, LabResultStore store)
    {
        using var document = await JsonDocument.ParseAsync(stream);
        var root = document.RootElement;
        if (!root.TryGetProperty("site", out var sites) || sites.ValueKind != JsonValueKind.Array)
            throw new JsonException("OWASP ZAP site array is required.");

        var alertCount = 0; var imported = 0; var mapped = 0; var unmapped = 0;
        var healthObserved = false; var dangerousHealthAlert = false;
        foreach (var site in sites.EnumerateArray())
        {
            if (!site.TryGetProperty("alerts", out var alerts) || alerts.ValueKind != JsonValueKind.Array) continue;
            foreach (var alert in alerts.EnumerateArray())
            {
                alertCount++;
                if (!alert.TryGetProperty("instances", out var instances) || instances.ValueKind != JsonValueKind.Array) continue;
                foreach (var instance in instances.EnumerateArray())
                {
                    var uri = Text(instance, "uri") ?? string.Empty;
                    var alertName = Text(alert, "alert") ?? Text(alert, "name") ?? string.Empty;
                    var caseId = MapCase(uri, alertName, Text(instance, "param"));
                    var dangerous = IsDangerous(alertName);
                    if (PathIs(uri, "/health"))
                    {
                        healthObserved = true;
                        if (dangerous) dangerousHealthAlert = true;
                    }
                    store.Add(CreateFinding(store, alert, instance, caseId));
                    imported++;
                    if (caseId == "DAST-UNMAPPED") unmapped++; else mapped++;
                }
            }
        }

        if (healthObserved)
        {
            store.Add(CreateFalsePositive(store, dangerousHealthAlert));
            imported++; mapped++;
        }
        return new DastImportSummary(alertCount, imported, mapped, unmapped);
    }

    private static string MapCase(string uri, string alert, string? parameter)
    {
        if (PathIs(uri, "/api/diagnostic") && parameter?.Contains("command", StringComparison.OrdinalIgnoreCase) == true)
            return "DAST-CRITICAL-001";
        if (PathIs(uri, "/api/search") && alert.Contains("cross site scripting", StringComparison.OrdinalIgnoreCase))
            return "DAST-HIGH-001";
        if (PathIs(uri, "/api/file") && (alert.Contains("traversal", StringComparison.OrdinalIgnoreCase) || alert.Contains("file", StringComparison.OrdinalIgnoreCase)))
            return "DAST-HIGH-002";
        if (PathIs(uri, "/api/redirect") && alert.Contains("redirect", StringComparison.OrdinalIgnoreCase))
            return "DAST-MEDIUM-001";
        if ((PathIs(uri, "/") || PathIs(uri, "/health")) && IsMissingHeader(alert))
            return "DAST-LOW-001";
        return "DAST-UNMAPPED";
    }

    private static LabExecutionResult CreateFinding(LabResultStore store, JsonElement alert,
        JsonElement instance, string caseId)
    {
        var pluginId = Text(alert, "pluginid") ?? Text(alert, "alertRef");
        var alertName = Text(alert, "alert") ?? Text(alert, "name");
        var uri = Text(instance, "uri") ?? string.Empty;
        var method = Text(instance, "method") ?? "GET";
        var parameter = Text(instance, "param");
        var attack = Text(instance, "attack");
        var evidenceText = Text(instance, "evidence");
        var severity = Risk(Text(alert, "riskcode"), Text(alert, "riskdesc"));
        var confidence = Text(alert, "confidence") ?? Text(alert, "confidencedesc");
        var evidence = new Dictionary<string, string?>
        {
            ["detected"] = "True", ["pluginId"] = pluginId, ["url"] = uri,
            ["method"] = method, ["parameter"] = parameter, ["attack"] = attack,
            ["evidence"] = evidenceText, ["risk"] = severity, ["confidence"] = confidence,
            ["expectedSeverity"] = ExpectedSeverity(caseId), ["observedSeverity"] = severity
        };
        return new LabExecutionResult(Guid.NewGuid(), DateTimeOffset.UtcNow, caseId, "DAST-IMPORT",
            uri, attack ?? parameter ?? string.Empty, "Detect the controlled runtime weakness.",
            $"ZAP reported {alertName} at {uri}.", caseId == "DAST-UNMAPPED" ? null : true,
            null, caseId == "DAST-UNMAPPED" ? "Additional ZAP alert requires manual review." : "Mapped OWASP ZAP alert.",
            "OWASP ZAP", RuleId: pluginId, Severity: severity, File: uri,
            Message: alertName, Source: "dast", TestRunId: store.TestRunId,
            Assertion: "The ZAP plugin, URL, parameter, attack, evidence, risk and confidence are retained.",
            Evidence: evidence);
    }

    private static LabExecutionResult CreateFalsePositive(LabResultStore store, bool dangerousAlert) => new(
        Guid.NewGuid(), DateTimeOffset.UtcNow, "DAST-FP-001", "DAST-IMPORT", "/health", "GET /health",
        "The health endpoint must not have an injection, XSS, traversal or redirect alert.",
        dangerousAlert ? "A dangerous ZAP alert was associated with /health." : "The scanned health endpoint has no dangerous alert.",
        !dangerousAlert, null, "Controlled DAST negative case.", "OWASP ZAP", Severity: "informational",
        File: "/health", Source: "dast", TestRunId: store.TestRunId,
        Assertion: "The scanned /health endpoint has no dangerous mapped alert.",
        FailureReason: dangerousAlert ? "ZAP associated a dangerous alert with /health." : null,
        Evidence: new Dictionary<string, string?>
        {
            ["detected"] = dangerousAlert.ToString(), ["expectedDetection"] = "False",
            ["url"] = "/health", ["validationStatus"] = dangerousAlert ? "failed" : "passed"
        });

    private static bool IsDangerous(string alert) =>
        alert.Contains("injection", StringComparison.OrdinalIgnoreCase) ||
        alert.Contains("cross site scripting", StringComparison.OrdinalIgnoreCase) ||
        alert.Contains("traversal", StringComparison.OrdinalIgnoreCase) ||
        alert.Contains("redirect", StringComparison.OrdinalIgnoreCase);

    private static bool IsMissingHeader(string alert) =>
        alert.Contains("header", StringComparison.OrdinalIgnoreCase) ||
        alert.Contains("content security policy", StringComparison.OrdinalIgnoreCase) ||
        alert.Contains("clickjacking", StringComparison.OrdinalIgnoreCase);

    private static bool PathIs(string uri, string expected)
    {
        if (Uri.TryCreate(uri, UriKind.Absolute, out var absolute)) return absolute.AbsolutePath.Equals(expected, StringComparison.OrdinalIgnoreCase);
        return uri.Split('?', 2)[0].Equals(expected, StringComparison.OrdinalIgnoreCase);
    }

    private static string Risk(string? code, string? description)
    {
        if (!string.IsNullOrWhiteSpace(description)) return description.Split(' ', 2)[0].ToLowerInvariant();
        return code switch { "3" => "high", "2" => "medium", "1" => "low", _ => "informational" };
    }

    private static string? ExpectedSeverity(string caseId) => caseId switch
    {
        "DAST-CRITICAL-001" => "critical",
        "DAST-HIGH-001" or "DAST-HIGH-002" => "high",
        "DAST-MEDIUM-001" => "medium",
        "DAST-LOW-001" => "low",
        _ => null
    };

    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
