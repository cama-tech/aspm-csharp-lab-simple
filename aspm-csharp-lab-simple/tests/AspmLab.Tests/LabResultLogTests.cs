using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class LabResultLogTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public LabResultLogTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    [Fact]
    public async Task VulnerableEndpoint_IsAutomaticallyRecorded()
    {
        await _client.DeleteAsync("/api/lab-results");
        await _client.GetAsync("/api/search?q=LOG-TEST");

        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results");
        var saved = Assert.Single(results!);
        Assert.Equal("BASELINE-SAST-001", saved.CaseId);
        Assert.Equal("/api/search", saved.Path);
        Assert.Equal("HTTP 200; assertion=passed", saved.Observed);
        Assert.True(saved.Passed);
        Assert.Equal(200, saved.ExpectedStatusCode);
        Assert.Equal(200, saved.ActualStatusCode);
        Assert.NotNull(saved.TestRunId);
        Assert.NotNull(saved.StartedAtUtc);
        Assert.NotNull(saved.CompletedAtUtc);
        Assert.Null(saved.FailureReason);
        Assert.Equal("True", saved.Evidence!["reflectedWithoutEncoding"]);
        Assert.Contains("q=LOG-TEST", saved.Input);
    }

    [Fact]
    public async Task RedirectLog_ContainsLocationEvidenceAndPassesAssertion()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/redirect?url=https%3A%2F%2Fexample.invalid");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results");
        var saved = Assert.Single(results!);
        Assert.True(saved.Passed);
        Assert.Equal("https://example.invalid", saved.Evidence!["location"]);
    }

    [Fact]
    public async Task RejectedCommand_IsRecordedAsSuccessfulSecurityAssertion()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/diagnostic?command=whoami%3B%20id");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results");
        var saved = Assert.Single(results!);
        Assert.True(saved.Passed);
        Assert.Equal(400, saved.ExpectedStatusCode);
        Assert.Equal("False", saved.Evidence!["allowlisted"]);
        Assert.Equal("False", saved.Evidence!["executed"]);
    }

    [Fact]
    public async Task PathTraversalLog_RecordsResolvedEscapedPath()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/file?name=../appsettings.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var saved = Assert.Single((await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results"))!);
        Assert.True(saved.Passed);
        Assert.Equal("True", saved.Evidence!["escapedLabRoot"]);
        Assert.Contains("appsettings.json", saved.Evidence["resolvedPath"]);
    }

    [Fact]
    public async Task SensitiveLogCase_RecordsMaskedEvidence()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.PostAsJsonAsync("/api/session/audit", new
        {
            email = "usuario@laboratorio.invalid",
            token = "TOKEN-FICTICIO"
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var saved = Assert.Single((await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results"))!);
        Assert.True(saved.Passed);
        Assert.Equal("True", saved.Evidence!["logWritten"]);
        Assert.Equal("usuario@laboratorio.invalid", saved.Evidence["email"]);
        Assert.NotEqual("TOKEN-FICTICIO", saved.Evidence["tokenMasked"]);
    }

    [Fact]
    public async Task UnsafeDeserializationLog_ConfirmsTypeNameHandlingAll()
    {
        await _client.DeleteAsync("/api/lab-results");
        var payload = Uri.EscapeDataString("{\"name\":\"PRUEBA\"}");
        var response = await _client.PostAsync($"/api/legacy/import?payload={payload}", null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var saved = Assert.Single((await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results"))!);
        Assert.True(saved.Passed);
        Assert.Equal("All", saved.Evidence!["typeNameHandling"]);
    }

    [Fact]
    public async Task FalsePositiveFixtureLog_SeparatesRuntimeReadinessFromSastClassification()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/public-id");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var saved = Assert.Single((await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results"))!);
        Assert.True(saved.Passed);
        Assert.Equal("True", saved.Evidence!["publicFictitiousIdentifierPresent"]);
        Assert.Equal("Pending external scanner review", saved.Evidence["sastClassification"]);
    }

    [Fact]
    public async Task ManualResult_CanBeExportedAsJsonFile()
    {
        await _client.DeleteAsync("/api/lab-results");
        var manual = new ManualLabResult(
            "NEW-SAST-001",
            "whoami executes",
            "Command returned the current user",
            true,
            "GET",
            "/api/diagnostic",
            "command=whoami",
            12.5,
            "Validated from Swagger");

        var created = await _client.PostAsJsonAsync("/api/lab-results", manual);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var exported = await _client.GetAsync("/api/lab-results/export");
        Assert.Equal(HttpStatusCode.OK, exported.StatusCode);
        Assert.Equal("application/json", exported.Content.Headers.ContentType?.MediaType);
        Assert.Contains("aspm-lab-results.json", exported.Content.Headers.ContentDisposition?.FileName ?? string.Empty);

        var exportedResults = JsonSerializer.Deserialize<List<LabExecutionResult>>(
            await exported.Content.ReadAsStringAsync(),
            new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

        var saved = Assert.Single(exportedResults!);
        Assert.Equal("NEW-SAST-001", saved.CaseId);
        Assert.True(saved.Passed);
    }
}
