using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class ContainerImportTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    public ContainerImportTests(WebApplicationFactory<Program> factory) => _client = factory.CreateClient();

    [Fact]
    public async Task ContainerExport_WithoutImport_ListsSevenPendingCases()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/lab-results/export/container");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("aspm-container-results.json", response.Content.Headers.ContentDisposition?.FileName ?? string.Empty);
        var report = await ReadReport(response);
        Assert.Equal(7, report.Summary.ExpectedCases);
        Assert.Equal(7, report.Summary.PendingCases);
        Assert.Equal(0, report.Summary.ImportedFindings);
        Assert.All(report.Results, item => Assert.Equal("CONTAINER-PENDING", item.Method));
    }

    [Fact]
    public async Task ImageAndConfigJson_ProduceSevenPassedCases()
    {
        await _client.DeleteAsync("/api/lab-results");
        using (var image = Form(ImageJson, "trivy-image-results.json"))
            Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-container", image)).StatusCode);
        using (var config = Form(ConfigJson, "trivy-config-results.json"))
            Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-container", config)).StatusCode);

        var report = await ReadReport(await _client.GetAsync("/api/lab-results/export/container"));
        Assert.Equal(7, report.Summary.PassedCases);
        Assert.Equal(0, report.Summary.FailedCases);
        Assert.Equal(0, report.Summary.PendingCases);
        Assert.Equal(6, report.Summary.ImportedFindings);
        Assert.Equal(0, report.Summary.UnmappedFindings);
        Assert.True(Assert.Single(report.Results.Where(item => item.CaseId == "CONTAINER-FP-001")).Passed);
    }

    [Fact]
    public async Task AdditionalVulnerability_IsPreservedAsUnmapped()
    {
        await _client.DeleteAsync("/api/lab-results");
        var json = ImageJson.Replace("\"Vulnerabilities\":[", "\"Vulnerabilities\":[{\"VulnerabilityID\":\"CVE-EXTRA\",\"PkgName\":\"Other.Package\",\"InstalledVersion\":\"1.0\",\"Severity\":\"HIGH\"},");
        using var form = Form(json, "trivy-image-results.json");
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-container", form)).StatusCode);
        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results/container");
        Assert.Contains(results!, item => item.CaseId == "CONTAINER-UNMAPPED" && item.Passed is null);
    }

    [Fact]
    public async Task PublicExposureFindingForCompose_FailsNegativeControl()
    {
        await _client.DeleteAsync("/api/lab-results");
        var json = ConfigJson.Replace("\"Misconfigurations\":[]", "\"Misconfigurations\":[{\"ID\":\"DS-LAB\",\"Title\":\"Public exposure on all interfaces 0.0.0.0\",\"Message\":\"Published publicly\",\"Severity\":\"HIGH\"}]");
        using var form = Form(json, "trivy-config-results.json");
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-container", form)).StatusCode);
        var report = await ReadReport(await _client.GetAsync("/api/lab-results/export/container"));
        Assert.False(Assert.Single(report.Results.Where(item => item.CaseId == "CONTAINER-FP-001")).Passed);
    }

    [Fact]
    public async Task ContainerQueryExcludesOtherReviewResults()
    {
        await _client.DeleteAsync("/api/lab-results");
        using (var form = Form(ImageJson, "trivy-image-results.json"))
            Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-container", form)).StatusCode);
        var other = new ManualLabResult("IAC-HIGH-001", "iac", "iac", true, "MANUAL", "infra", "", null, "control");
        Assert.Equal(HttpStatusCode.Created, (await _client.PostAsJsonAsync("/api/lab-results", other)).StatusCode);
        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results/container");
        Assert.All(results!, item => Assert.StartsWith("CONTAINER-", item.CaseId));
    }

    [Fact]
    public async Task InvalidTrivyJson_IsRejected()
    {
        using var form = Form("{ invalid", "trivy.json");
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsync("/api/lab-results/import-container", form)).StatusCode);
    }

    private static MultipartFormDataContent Form(string json, string name)
    {
        var form = new MultipartFormDataContent();
        form.Add(new StringContent(json, Encoding.UTF8, "application/json"), "file", name);
        return form;
    }

    private static async Task<ContainerExportReport> ReadReport(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<ContainerExportReport>(await response.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

    private const string ImageJson = """
    {"Results":[{"Target":"aspm-lab:local","Class":"lang-pkgs","Type":"dotnet-core",
      "Vulnerabilities":[
        {"VulnerabilityID":"CVE-CRITICAL","PkgName":"DNS","InstalledVersion":"6.1.0","FixedVersion":"7.0.0","Severity":"CRITICAL","Title":"Critical DNS issue"},
        {"VulnerabilityID":"CVE-HIGH","PkgName":"Newtonsoft.Json","InstalledVersion":"12.0.1","FixedVersion":"13.0.1","Severity":"HIGH","Title":"High JSON issue"},
        {"VulnerabilityID":"CVE-MEDIUM","PkgName":"SixLabors.ImageSharp","InstalledVersion":"2.1.3","FixedVersion":"3.1.0","Severity":"MEDIUM","Title":"Medium image issue"},
        {"VulnerabilityID":"CVE-LOW","PkgName":"EnumStringValues","InstalledVersion":"4.0.0","FixedVersion":"4.1.0","Severity":"LOW","Title":"Low enum issue"}
      ]}]}
    """;

    private const string ConfigJson = """
    {"Results":[
      {"Target":"Dockerfile","Class":"config","Type":"dockerfile","Misconfigurations":[
        {"ID":"DS002","Title":"Image runs as root user","Message":"Specify a non-root USER","Severity":"HIGH","CauseMetadata":{"StartLine":8,"EndLine":12}},
        {"ID":"DS026","Title":"No HEALTHCHECK instruction","Message":"Add HEALTHCHECK","Severity":"LOW","CauseMetadata":{"StartLine":8,"EndLine":12}}
      ]},
      {"Target":"docker-compose.yml","Class":"config","Type":"docker-compose","Misconfigurations":[]}
    ]}
    """;
}
