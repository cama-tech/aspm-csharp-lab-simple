using System.Text.RegularExpressions;
using Xunit;

namespace AspmLab.Tests;

public class SecretsFixtureTests
{
    [Theory]
    [InlineData("ASPM_LAB_AWS_[A-Z0-9]{16,20}")]
    [InlineData("ghp_LAB[A-Za-z0-9]{20,40}")]
    [InlineData("LAB_PASSWORD=[A-Za-z0-9!@#$%^&*]{12,}")]
    [InlineData("LAB_INTERNAL_KEY=test-key-[0-9]{5}")]
    public void DetectableSecretFixture_MatchesControlledPattern(string pattern)
    {
        Assert.Matches(new Regex(pattern), RepositoryFixture.Read("fixtures/secrets/detectable-secrets.env"));
    }

    [Fact]
    public void PublicExample_IsSeparatedAndAllowlisted()
    {
        var config = RepositoryFixture.Read(".gitleaks.toml");
        var examples = RepositoryFixture.Read("fixtures/secrets/known-false-positives.txt");
        Assert.Contains("known-false-positives.txt", config);
        Assert.Contains("PUBLIC_DOC_ID", examples);
    }
}
