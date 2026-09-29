using Xunit;

namespace AspmLab.Tests;

public class SbomFixtureTests
{
    [Fact]
    public void SbomProject_ContainsComponentsToInventory()
    {
        var project = RepositoryFixture.Read("src/AspmLab/AspmLab.csproj");
        Assert.Contains("PackageReference", project);
        Assert.Contains("RestorePackagesWithLockFile", project);
    }

    [Fact]
    public void Catalog_SeparatesSbomInventoryFromVulnerabilities()
    {
        var items = RepositoryFixture.ExpectedCases().Where(item => item.Review == "SBOM").ToList();
        Assert.Equal(9, items.Count);
        Assert.All(items, item => Assert.Equal("informational", item.ExpectedSeverity));
        Assert.Equal(8, items.Count(item => item.ExpectedClassification == "inventory"));
        Assert.Single(items.Where(item => item.ExpectedClassification == "false_positive"));
    }
}
