using Xunit;

namespace AspmLab.Tests;

public class CatalogTests
{
    [Fact]
    public void Catalog_ContainsEveryReview()
    {
        var reviews = RepositoryFixture.ExpectedCases().Select(item => item.Review).ToHashSet();
        foreach (var expected in new[] { "SAST", "SCA", "Secrets", "SBOM", "IaC", "Container", "DAST", "Business" })
            Assert.Contains(expected, reviews);
    }

    [Fact]
    public void Catalog_ContainsCriticalHighMediumAndLow()
    {
        var severities = RepositoryFixture.ExpectedCases().Select(item => item.ExpectedSeverity).ToHashSet();
        foreach (var expected in new[] { "critical", "high", "medium", "low" })
            Assert.Contains(expected, severities);
    }

    [Fact]
    public void Catalog_ContainsThreeFalsePositives()
    {
        Assert.True(RepositoryFixture.ExpectedCases().Count(item => item.ExpectedClassification == "false_positive") >= 3);
    }

    [Fact]
    public void Catalog_ContainsCrossToolDuplicate()
    {
        var duplicate = RepositoryFixture.ExpectedCases()
            .Where(item => item.DuplicateGroup == "XSS-SEARCH")
            .Select(item => item.Review)
            .ToHashSet();
        Assert.Contains("SAST", duplicate);
        Assert.Contains("DAST", duplicate);
    }

    [Fact]
    public void Catalog_ContainsFortyEightUniqueControlledCases()
    {
        var cases = RepositoryFixture.ExpectedCases();

        Assert.Equal(48, cases.Count);
        Assert.Equal(48, cases.Select(item => item.Id).Distinct().Count());
    }

    [Theory]
    [MemberData(nameof(CatalogCaseIds))]
    public void EveryCatalogCase_HasAReviewSeverityAndClassification(string caseId)
    {
        var item = Assert.Single(RepositoryFixture.ExpectedCases().Where(item => item.Id == caseId));
        Assert.False(string.IsNullOrWhiteSpace(item.Review));
        Assert.False(string.IsNullOrWhiteSpace(item.ExpectedSeverity));
        Assert.False(string.IsNullOrWhiteSpace(item.ExpectedClassification));
        Assert.False(string.IsNullOrWhiteSpace(item.Location));
    }

    public static IEnumerable<object[]> CatalogCaseIds() =>
        RepositoryFixture.ExpectedCases().Select(item => new object[] { item.Id });
}
