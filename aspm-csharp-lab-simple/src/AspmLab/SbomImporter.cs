using System.Text.Json;

public sealed record SbomImportSummary(int ComponentsScanned, int Imported, int Mapped, int Unmapped);

public static class SbomImporter
{
    private static readonly Dictionary<string, (string CaseId, string Version)> ExpectedPackages =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["Newtonsoft.Json"] = ("SBOM-DIRECT-001", "12.0.1"),
            ["System.Text.Encodings.Web"] = ("SBOM-DIRECT-002", "4.7.0"),
            ["SixLabors.ImageSharp"] = ("SBOM-DIRECT-003", "2.1.3"),
            ["DNS"] = ("SBOM-DIRECT-004", "6.1.0"),
            ["EnumStringValues"] = ("SBOM-DIRECT-005", "4.0.0")
        };

    public static async Task<SbomImportSummary> ImportAsync(Stream stream, LabResultStore store)
    {
        using var document = await JsonDocument.ParseAsync(stream);
        var root = document.RootElement;
        if (!root.TryGetProperty("bomFormat", out var format) || format.GetString() != "CycloneDX")
            throw new JsonException("bomFormat must be CycloneDX.");

        var components = root.TryGetProperty("components", out var array) && array.ValueKind == JsonValueKind.Array
            ? array.EnumerateArray().ToList()
            : new List<JsonElement>();
        var directRefs = DirectReferences(root);
        var mapped = 0;
        var imported = 0;
        var now = DateTimeOffset.UtcNow;

        var metadataComponent = root.TryGetProperty("metadata", out var metadata) &&
                                metadata.TryGetProperty("component", out var application)
            ? application
            : default;
        if (metadataComponent.ValueKind == JsonValueKind.Object)
        {
            AddComponent(store, metadataComponent, "SBOM-APP-001", true, true, now, "application");
            imported++; mapped++;
        }

        foreach (var component in components)
        {
            var name = Text(component, "name") ?? "unknown";
            var version = Text(component, "version") ?? string.Empty;
            var bomRef = Text(component, "bom-ref") ?? string.Empty;
            var direct = directRefs.Contains(bomRef);
            var caseId = ExpectedPackages.TryGetValue(name, out var expected)
                ? expected.CaseId
                : direct ? "SBOM-UNMAPPED" : "SBOM-TRANSITIVE-001";
            var versionMatches = !ExpectedPackages.TryGetValue(name, out expected) || expected.Version == version;
            AddComponent(store, component, caseId, direct, versionMatches, now, "component");
            imported++;
            if (caseId != "SBOM-UNMAPPED") mapped++;
        }

        AddLicenseResult(store, components, now);
        AddNegativeControl(store, components, now);
        return new SbomImportSummary(components.Count + (metadataComponent.ValueKind == JsonValueKind.Object ? 1 : 0),
            imported + 2, mapped + 2, imported + 2 - (mapped + 2));
    }

    private static HashSet<string> DirectReferences(JsonElement root)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        if (!root.TryGetProperty("metadata", out var metadata) ||
            !metadata.TryGetProperty("component", out var app)) return result;
        var appRef = Text(app, "bom-ref");
        if (appRef is null || !root.TryGetProperty("dependencies", out var dependencies)) return result;
        foreach (var dependency in dependencies.EnumerateArray())
        {
            if (Text(dependency, "ref") != appRef || !dependency.TryGetProperty("dependsOn", out var dependsOn)) continue;
            foreach (var item in dependsOn.EnumerateArray())
                if (item.GetString() is { } value) result.Add(value);
        }
        return result;
    }

    private static void AddComponent(LabResultStore store, JsonElement component, string caseId,
        bool direct, bool passed, DateTimeOffset now, string kind)
    {
        var name = Text(component, "name") ?? "unknown";
        var version = Text(component, "version") ?? string.Empty;
        var purl = Text(component, "purl");
        var bomRef = Text(component, "bom-ref");
        var evidence = new Dictionary<string, string?>
        {
            ["name"] = name, ["version"] = version, ["purl"] = purl,
            ["bomRef"] = bomRef, ["direct"] = direct.ToString(), ["kind"] = kind
        };
        store.Add(new LabExecutionResult(Guid.NewGuid(), now, caseId, "SBOM-IMPORT", "bom.json",
            $"{name} {version}", "Component is present with the expected identity and relationship.",
            $"Imported {name} {version}; direct={direct}.", passed, null,
            "Imported from CycloneDX JSON.", "CycloneDX", Severity: "informational",
            Message: $"SBOM component {name} {version}", Source: "sbom", TestRunId: store.TestRunId,
            Assertion: "The component, version and relationship match the controlled inventory.",
            FailureReason: passed ? null : "The component version does not match the expected version.", Evidence: evidence));
    }

    private static void AddLicenseResult(LabResultStore store, IReadOnlyList<JsonElement> components, DateTimeOffset now)
    {
        var licensed = components.FirstOrDefault(HasLicense);
        var found = licensed.ValueKind == JsonValueKind.Object;
        store.Add(Result(store, now, "SBOM-LICENSE-001", found,
            found ? Text(licensed, "name") ?? "component" : "none",
            found ? "At least one component includes license information." : "No component includes license information."));
    }

    private static void AddNegativeControl(LabResultStore store, IReadOnlyList<JsonElement> components, DateTimeOffset now)
    {
        var present = components.Any(item => string.Equals(Text(item, "name"), "Fake.Vulnerable.Package", StringComparison.OrdinalIgnoreCase));
        store.Add(Result(store, now, "SBOM-FP-001", !present, "Fake.Vulnerable.Package 1.0.0",
            present ? "The textual-only fake package was incorrectly inventoried." : "The textual-only fake package is absent."));
    }

    private static LabExecutionResult Result(LabResultStore store, DateTimeOffset now, string caseId,
        bool passed, string input, string observed) => new(Guid.NewGuid(), now, caseId, "SBOM-IMPORT", "bom.json",
        input, "Validate the controlled SBOM case.", observed, passed, null, "Imported from CycloneDX JSON.",
        "CycloneDX", Severity: "informational", Source: "sbom", TestRunId: store.TestRunId,
        Assertion: "The CycloneDX inventory satisfies the expected case.",
        FailureReason: passed ? null : observed,
        Evidence: new Dictionary<string, string?> { ["validationStatus"] = passed ? "passed" : "failed" });

    private static bool HasLicense(JsonElement component) =>
        component.TryGetProperty("licenses", out var licenses) && licenses.ValueKind == JsonValueKind.Array && licenses.GetArrayLength() > 0;
    private static string? Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
