using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class DastImportTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    public DastImportTests(WebApplicationFactory<Program> factory) => _client = factory.CreateClient();

    [Fact]
    public async Task DastExport_WithoutImport_ListsSixPendingCases()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/lab-results/export/dast");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("aspm-dast-results.json", response.Content.Headers.ContentDisposition?.FileName ?? string.Empty);
        var report = await ReadReport(response);
        Assert.Equal(6, report.Summary.ExpectedCases);
        Assert.Equal(6, report.Summary.PendingCases);
        Assert.Equal(0, report.Summary.ImportedFindings);
        Assert.All(report.Results, item => Assert.Equal("DAST-PENDING", item.Method));
    }

    [Fact]
    public async Task ZapJson_MapsFiveAlertsAndApprovesHealthControl()
    {
        await _client.DeleteAsync("/api/lab-results");
        using var form = Form(ValidZapJson);
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-dast", form)).StatusCode);
        var report = await ReadReport(await _client.GetAsync("/api/lab-results/export/dast"));
        Assert.Equal(6, report.Summary.PassedCases);
        Assert.Equal(0, report.Summary.FailedCases);
        Assert.Equal(0, report.Summary.PendingCases);
        Assert.Equal(5, report.Summary.ImportedFindings);
        Assert.Equal(0, report.Summary.UnmappedFindings);
        Assert.True(Assert.Single(report.Results.Where(item => item.CaseId == "DAST-FP-001")).Passed);
    }

    [Fact]
    public async Task AdditionalZapAlert_IsPreservedAsUnmapped()
    {
        await _client.DeleteAsync("/api/lab-results");
        var json = ValidZapJson.Replace("\"alerts\":[", "\"alerts\":[{\"pluginid\":\"99999\",\"alert\":\"Other informational alert\",\"riskcode\":\"0\",\"instances\":[{\"uri\":\"http://localhost:8080/other\",\"method\":\"GET\"}]},");
        using var form = Form(json);
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-dast", form)).StatusCode);
        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results/dast");
        Assert.Contains(results!, item => item.CaseId == "DAST-UNMAPPED" && item.Passed is null);
    }

    [Fact]
    public async Task DangerousHealthAlert_FailsFalsePositiveControl()
    {
        await _client.DeleteAsync("/api/lab-results");
        var json = ValidZapJson.Replace("\"alerts\":[", "\"alerts\":[{\"pluginid\":\"40012\",\"alert\":\"Cross Site Scripting\",\"riskcode\":\"3\",\"instances\":[{\"uri\":\"http://localhost:8080/health\",\"method\":\"GET\",\"param\":\"q\"}]},");
        using var form = Form(json);
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-dast", form)).StatusCode);
        var report = await ReadReport(await _client.GetAsync("/api/lab-results/export/dast"));
        Assert.False(Assert.Single(report.Results.Where(item => item.CaseId == "DAST-FP-001")).Passed);
    }

    [Fact]
    public async Task DastQueryExcludesFunctionalAndOtherReviewRecords()
    {
        await _client.DeleteAsync("/api/lab-results");
        using (var form = Form(ValidZapJson))
            Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-dast", form)).StatusCode);
        var other = new ManualLabResult("NEW-SAST-001", "runtime", "passed", true, "GET", "/api/diagnostic", "", null, "control");
        Assert.Equal(HttpStatusCode.Created, (await _client.PostAsJsonAsync("/api/lab-results", other)).StatusCode);
        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results/dast");
        Assert.All(results!, item => Assert.StartsWith("DAST-", item.CaseId));
    }

    [Fact]
    public async Task InvalidZapJson_IsRejected()
    {
        using var form = Form("{ invalid");
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsync("/api/lab-results/import-dast", form)).StatusCode);
    }

    private static MultipartFormDataContent Form(string json)
    {
        var form = new MultipartFormDataContent();
        form.Add(new StringContent(json, Encoding.UTF8, "application/json"), "file", "zap-results.json");
        return form;
    }

    private static async Task<DastExportReport> ReadReport(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<DastExportReport>(await response.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

    private const string ValidZapJson = """
    {"site":[{"@name":"http://localhost:8080","alerts":[
      {"pluginid":"90020","alert":"Remote OS Command Injection","riskcode":"3","confidence":"2","instances":[{"uri":"http://localhost:8080/api/diagnostic?command=whoami","method":"GET","param":"command","attack":"whoami","evidence":"executed=true"}]},
      {"pluginid":"40012","alert":"Cross Site Scripting (Reflected)","riskcode":"3","confidence":"2","instances":[{"uri":"http://localhost:8080/api/search?q=test","method":"GET","param":"q","attack":"<script>alert(1)</script>","evidence":"<script>alert(1)</script>"}]},
      {"pluginid":"6","alert":"Path Traversal","riskcode":"3","confidence":"2","instances":[{"uri":"http://localhost:8080/api/file?name=../appsettings.json","method":"GET","param":"name","attack":"../appsettings.json","evidence":"Logging"}]},
      {"pluginid":"10028","alert":"Open Redirect","riskcode":"2","confidence":"2","instances":[{"uri":"http://localhost:8080/api/redirect?url=https://example.invalid","method":"GET","param":"url","attack":"https://example.invalid","evidence":"Location: https://example.invalid"}]},
      {"pluginid":"10021","alert":"X-Content-Type-Options Header Missing","riskcode":"1","confidence":"2","instances":[{"uri":"http://localhost:8080/health","method":"GET","param":"","attack":"","evidence":""}]}
    ]}]}
    """;
}
