using Xunit;

namespace AspmLab.Tests;

public class SastFixtureTests
{
    [Theory]
    [InlineData("NEW-SAST-001")]
    [InlineData("BASELINE-SAST-001")]
    [InlineData("BASELINE-SAST-002")]
    [InlineData("BASELINE-SAST-003")]
    [InlineData("MEDIUM-SAST-001")]
    [InlineData("LOW-SAST-001")]
    [InlineData("SECRET-FP-001")]
    public void Program_ContainsControlledSastMarker(string marker)
    {
        Assert.Contains(marker, RepositoryFixture.Read("src/AspmLab/Program.cs"));
    }
}
