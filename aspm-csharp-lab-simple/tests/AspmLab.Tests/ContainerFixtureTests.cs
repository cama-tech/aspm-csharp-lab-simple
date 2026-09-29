using Xunit;

namespace AspmLab.Tests;

public class ContainerFixtureTests
{
    [Fact]
    public void Dockerfile_PreservesRootExecutionCase()
    {
        var dockerfile = RepositoryFixture.Read("Dockerfile");
        Assert.Contains("LAB-CONTAINER-001", dockerfile);
        Assert.DoesNotContain("\nUSER ", dockerfile, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Dockerfile_PreservesMissingHealthcheckCase()
    {
        Assert.DoesNotContain("HEALTHCHECK", RepositoryFixture.Read("Dockerfile"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Catalog_ContainsSevenContainerCasesIncludingFalsePositive()
    {
        var cases = RepositoryFixture.ExpectedCases().Where(item => item.Review == "Container").ToList();
        Assert.Equal(7, cases.Count);
        Assert.Single(cases.Where(item => item.ExpectedClassification == "false_positive"));
        foreach (var severity in new[] { "critical", "high", "medium", "low" })
            Assert.Contains(cases, item => item.ExpectedSeverity == severity);
    }
}
