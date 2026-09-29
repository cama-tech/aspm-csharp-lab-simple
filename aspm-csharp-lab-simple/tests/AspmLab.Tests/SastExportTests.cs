using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class SastExportTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    public SastExportTests(WebApplicationFactory<Program> factory) => _client = factory.CreateClient();

    [Fact]
    public async Task SastExport_WithoutSarif_ListsSevenPendingCases()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/lab-results/export/sast");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("aspm-sast-results.json", response.Content.Headers.ContentDisposition?.FileName ?? string.Empty);
        var report = JsonSerializer.Deserialize<SastExportReport>(
            await response.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.NotNull(report);
        Assert.Equal(7, report.Summary.ExpectedCases);
        Assert.Equal(7, report.Summary.PendingCases);
        Assert.Equal(7, report.Results.Count);
        Assert.All(report.Results, item => Assert.Equal("SAST-PENDING", item.Method));
    }

    [Fact]
    public async Task SastQueryAndExport_ExcludeNonSastResults()
    {
        await _client.DeleteAsync("/api/lab-results");
        var manual = new ManualLabResult("SECRET-LOW-001", "secret", "secret", true,
            "MANUAL", "file", "[REDACTED]", null, "Non-SAST control");
        Assert.Equal(HttpStatusCode.Created, (await _client.PostAsJsonAsync("/api/lab-results", manual)).StatusCode);

        var sast = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results/sast");
        Assert.Empty(sast!);
        var export = await _client.GetAsync("/api/lab-results/export/sast");
        var report = JsonSerializer.Deserialize<SastExportReport>(
            await export.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.NotNull(report);
        Assert.Equal(7, report.Results.Count);
        Assert.DoesNotContain(report.Results, item => item.CaseId == "SECRET-LOW-001");
    }

    [Fact]
    public async Task RuntimeEvidence_DoesNotCountAsSarifDetection()
    {
        await _client.DeleteAsync("/api/lab-results");
        var runtime = new ManualLabResult("BASELINE-SAST-001", "runtime", "passed", true,
            "GET", "/api/search", "?q=test", null, "Functional evidence only");
        Assert.Equal(HttpStatusCode.Created, (await _client.PostAsJsonAsync("/api/lab-results", runtime)).StatusCode);

        var export = await _client.GetAsync("/api/lab-results/export/sast");
        var report = JsonSerializer.Deserialize<SastExportReport>(await export.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.NotNull(report);
        Assert.Equal(0, report.Summary.PassedCases);
        Assert.Equal(7, report.Summary.PendingCases);
        Assert.Equal(0, report.Summary.ImportedFindings);
        Assert.All(report.Results, item => Assert.Equal("SAST-PENDING", item.Method));
    }
}
