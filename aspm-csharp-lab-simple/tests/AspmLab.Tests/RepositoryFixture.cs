using System.Text.Json;

namespace AspmLab.Tests;

internal static class RepositoryFixture
{
    public static string Root { get; } = FindRoot();

    public static string Read(string relativePath) =>
        File.ReadAllText(Path.Combine(Root, relativePath.Replace('/', Path.DirectorySeparatorChar)));

    public static IReadOnlyList<ExpectedCase> ExpectedCases()
    {
        using var document = JsonDocument.Parse(Read("evidence/expected-findings.json"));
        return document.RootElement.GetProperty("cases").EnumerateArray()
            .Select(item => new ExpectedCase(
                item.GetProperty("id").GetString()!,
                item.GetProperty("review").GetString()!,
                item.GetProperty("location").GetString()!,
                item.GetProperty("marker").GetString()!,
                item.GetProperty("expectedSeverity").GetString()!,
                item.GetProperty("expectedClassification").GetString()!,
                item.TryGetProperty("duplicateGroup", out var group) && group.ValueKind == JsonValueKind.String
                    ? group.GetString()
                    : null))
            .ToList();
    }

    private static string FindRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "README.md")) &&
                Directory.Exists(Path.Combine(current.FullName, "evidence")))
                return current.FullName;
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("Repository root was not found from the test output directory.");
    }
}

internal sealed record ExpectedCase(
    string Id,
    string Review,
    string Location,
    string Marker,
    string ExpectedSeverity,
    string ExpectedClassification,
    string? DuplicateGroup);

