using System.Xml.Linq;
using Xunit;

namespace AspmLab.Tests;

public class ScaFixtureTests
{
    [Theory]
    [InlineData("DNS", "6.1.0")]
    [InlineData("EnumStringValues", "4.0.0")]
    [InlineData("Newtonsoft.Json", "12.0.1")]
    [InlineData("System.Text.Encodings.Web", "4.7.0")]
    [InlineData("SixLabors.ImageSharp", "2.1.3")]
    public void VulnerableProject_ContainsExpectedPackage(string name, string version)
    {
        var document = XDocument.Parse(RepositoryFixture.Read("src/AspmLab/AspmLab.csproj"));
        var reference = document.Descendants("PackageReference")
            .SingleOrDefault(item => item.Attribute("Include")?.Value == name);
        Assert.NotNull(reference);
        Assert.Equal(version, reference!.Attribute("Version")?.Value);
    }

    [Fact]
    public void FalsePositiveControl_IsTextAndNotAPackageReference()
    {
        var project = XDocument.Parse(RepositoryFixture.Read("src/AspmLab/AspmLab.csproj"));
        Assert.DoesNotContain(project.Descendants("PackageReference"), item =>
            item.Attribute("Include")?.Value == "Fake.Vulnerable.Package");
        Assert.Contains("Fake.Vulnerable.Package", RepositoryFixture.Read("src/AspmLab/ScaFalsePositiveFixtures.cs"));
    }
}
