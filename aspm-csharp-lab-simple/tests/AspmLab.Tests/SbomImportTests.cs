using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class SbomImportTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    public SbomImportTests(WebApplicationFactory<Program> factory) => _client = factory.CreateClient();

    [Fact]
    public async Task SbomExport_WithoutImport_ListsNinePendingCases()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/lab-results/export/sbom");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("aspm-sbom-results.json", response.Content.Headers.ContentDisposition?.FileName ?? string.Empty);
        var report = await ReadReport(response);
        Assert.Equal(9, report.Summary.ExpectedCases);
        Assert.Equal(0, report.Summary.PassedCases);
        Assert.Equal(9, report.Summary.PendingCases);
        Assert.Equal(0, report.Summary.ImportedComponents);
        Assert.All(report.Results, item => Assert.Equal("SBOM-PENDING", item.Method));
    }

    [Fact]
    public async Task CycloneDxJson_ImportsExpectedInventoryAndNegativeControl()
    {
        await _client.DeleteAsync("/api/lab-results");
        using var form = Form(ValidCycloneDx);
        var imported = await _client.PostAsync("/api/lab-results/import-sbom", form);
        Assert.Equal(HttpStatusCode.OK, imported.StatusCode);

        var response = await _client.GetAsync("/api/lab-results/export/sbom");
        var report = await ReadReport(response);
        Assert.Equal(9, report.Summary.ExpectedCases);
        Assert.Equal(9, report.Summary.PassedCases);
        Assert.Equal(0, report.Summary.FailedCases);
        Assert.Equal(0, report.Summary.PendingCases);
        Assert.Equal(7, report.Summary.ImportedComponents);
        Assert.Equal(0, report.Summary.AdditionalComponents);
        Assert.True(Assert.Single(report.Results.Where(item => item.CaseId == "SBOM-FP-001")).Passed);
        Assert.Equal("False", Assert.Single(report.Results.Where(item => item.CaseId == "SBOM-TRANSITIVE-001")).Evidence!["direct"]);
    }

    [Fact]
    public async Task WrongPackageVersion_FailsExpectedComponent()
    {
        await _client.DeleteAsync("/api/lab-results");
        using var form = Form(ValidCycloneDx.Replace("12.0.1", "99.0.0"));
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-sbom", form)).StatusCode);
        var report = await ReadReport(await _client.GetAsync("/api/lab-results/export/sbom"));
        var result = Assert.Single(report.Results.Where(item => item.CaseId == "SBOM-DIRECT-001"));
        Assert.False(result.Passed);
        Assert.NotNull(result.FailureReason);
    }

    [Fact]
    public async Task TextualFakePackage_InSbomFailsNegativeControl()
    {
        await _client.DeleteAsync("/api/lab-results");
        var json = ValidCycloneDx.Replace("] , \"dependencies\"", ", {\"type\":\"library\",\"name\":\"Fake.Vulnerable.Package\",\"version\":\"1.0.0\",\"bom-ref\":\"pkg:nuget/Fake.Vulnerable.Package@1.0.0\"}] , \"dependencies\"");
        using var form = Form(json);
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-sbom", form)).StatusCode);
        var report = await ReadReport(await _client.GetAsync("/api/lab-results/export/sbom"));
        Assert.False(Assert.Single(report.Results.Where(item => item.CaseId == "SBOM-FP-001")).Passed);
    }

    [Fact]
    public async Task InvalidCycloneDxJson_IsRejected()
    {
        using var form = Form("{ invalid");
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsync("/api/lab-results/import-sbom", form)).StatusCode);
    }

    private static MultipartFormDataContent Form(string json)
    {
        var form = new MultipartFormDataContent();
        form.Add(new StringContent(json, Encoding.UTF8, "application/json"), "file", "bom.json");
        return form;
    }

    private static async Task<SbomExportReport> ReadReport(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<SbomExportReport>(await response.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

    private const string ValidCycloneDx = """
    { "bomFormat":"CycloneDX", "specVersion":"1.5",
      "metadata":{"component":{"type":"application","name":"AspmLab","version":"1.0.0","bom-ref":"app:AspmLab"}},
      "components":[
        {"type":"library","name":"Newtonsoft.Json","version":"12.0.1","bom-ref":"pkg:nuget/Newtonsoft.Json@12.0.1","purl":"pkg:nuget/Newtonsoft.Json@12.0.1","licenses":[{"license":{"id":"MIT"}}]},
        {"type":"library","name":"System.Text.Encodings.Web","version":"4.7.0","bom-ref":"pkg:nuget/System.Text.Encodings.Web@4.7.0"},
        {"type":"library","name":"SixLabors.ImageSharp","version":"2.1.3","bom-ref":"pkg:nuget/SixLabors.ImageSharp@2.1.3"},
        {"type":"library","name":"DNS","version":"6.1.0","bom-ref":"pkg:nuget/DNS@6.1.0"},
        {"type":"library","name":"EnumStringValues","version":"4.0.0","bom-ref":"pkg:nuget/EnumStringValues@4.0.0"},
        {"type":"library","name":"Transitive.Helper","version":"1.2.3","bom-ref":"pkg:nuget/Transitive.Helper@1.2.3"}
      ] , "dependencies":[
        {"ref":"app:AspmLab","dependsOn":["pkg:nuget/Newtonsoft.Json@12.0.1","pkg:nuget/System.Text.Encodings.Web@4.7.0","pkg:nuget/SixLabors.ImageSharp@2.1.3","pkg:nuget/DNS@6.1.0","pkg:nuget/EnumStringValues@4.0.0"]},
        {"ref":"pkg:nuget/Newtonsoft.Json@12.0.1","dependsOn":["pkg:nuget/Transitive.Helper@1.2.3"]}
      ] }
    """;
}
