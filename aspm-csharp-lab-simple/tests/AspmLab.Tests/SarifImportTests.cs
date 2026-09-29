using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class SarifImportTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public SarifImportTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task SarifFile_IsImportedAndCorrelatedWithExpectedCase()
    {
        await _client.DeleteAsync("/api/lab-results");
        const string sarif = """
        {
          "version": "2.1.0",
          "runs": [{
            "tool": { "driver": {
              "name": "Example SAST",
              "semanticVersion": "1.2.3",
              "rules": [{
                "id": "CS-COMMAND-INJECTION",
                "properties": { "security-severity": "9.8" }
              }]
            }},
            "results": [{
              "ruleId": "CS-COMMAND-INJECTION",
              "level": "error",
              "message": { "text": "Possible OS command injection through ProcessStartInfo" },
              "locations": [{ "physicalLocation": {
                "artifactLocation": { "uri": "src/AspmLab/Program.cs" },
                "region": { "startLine": 70 }
              }}]
            }]
          }]
        }
        """;

        using var form = new MultipartFormDataContent();
        form.Add(new StringContent(sarif, Encoding.UTF8, "application/json"), "file", "results.sarif");
        var response = await _client.PostAsync("/api/lab-results/import-sast", form);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var summary = await response.Content.ReadFromJsonAsync<SarifImportSummary>();
        Assert.Equal(1, summary!.Imported);
        Assert.Equal(1, summary.Mapped);
        Assert.Equal(0, summary.Unmapped);

        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results");
        var finding = Assert.Single(results!);
        Assert.Equal("NEW-SAST-001", finding.CaseId);
        Assert.Equal("Example SAST", finding.Tool);
        Assert.Equal("1.2.3", finding.ToolVersion);
        Assert.Equal("CS-COMMAND-INJECTION", finding.RuleId);
        Assert.Equal("critical", finding.Severity);
        Assert.Equal("src/AspmLab/Program.cs", finding.File);
        Assert.Equal(70, finding.Line);
        Assert.Equal("sarif", finding.Source);
    }

    [Fact]
    public async Task InvalidSarif_IsRejected()
    {
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent("{ invalid", Encoding.UTF8, "application/json"), "file", "invalid.sarif");
        var response = await _client.PostAsync("/api/lab-results/import-sast", form);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}

