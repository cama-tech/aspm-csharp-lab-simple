using Xunit;

namespace AspmLab.Tests;

public class IacFixtureTests
{
    [Theory]
    [InlineData("LAB-IAC-CRITICAL-001")]
    [InlineData("LAB-IAC-001")]
    [InlineData("LAB-IAC-MEDIUM-001")]
    [InlineData("LAB-IAC-LOW-001")]
    public void Terraform_ContainsControlledMisconfiguration(string marker)
    {
        Assert.Contains(marker, RepositoryFixture.Read("infra/main.tf"));
    }

    [Fact]
    public void LocalhostRule_IsTheControlledFalsePositive()
    {
        var fixture = RepositoryFixture.Read("infra/false-positive.tf");
        Assert.Contains("IAC-FP-001", fixture);
        Assert.Contains("127.0.0.1/32", fixture);
        Assert.DoesNotContain("0.0.0.0/0", fixture);
    }
}
