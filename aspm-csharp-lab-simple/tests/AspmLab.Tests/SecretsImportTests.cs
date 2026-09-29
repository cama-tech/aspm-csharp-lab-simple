using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class SecretsImportTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    public SecretsImportTests(WebApplicationFactory<Program> factory) => _client = factory.CreateClient();

    [Fact]
    public async Task SecretsExport_WithoutImport_ListsFivePendingCases()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/lab-results/export/secrets");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var report = JsonSerializer.Deserialize<SecretsExportReport>(
            await response.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.NotNull(report);
        Assert.Equal(5, report.Summary.ExpectedCases);
        Assert.Equal(5, report.Summary.PendingCases);
        Assert.Equal(5, report.Results.Count);
        Assert.All(report.Results, item => Assert.Null(item.Passed));
    }

    [Fact]
    public async Task GitleaksJson_ValidatesFourSecretsAndFalsePositiveControl()
    {
        await _client.DeleteAsync("/api/lab-results");
        using var form = Form(ValidGitleaksJson);
        var imported = await _client.PostAsync("/api/lab-results/import-secrets", form);
        Assert.Equal(HttpStatusCode.OK, imported.StatusCode);

        var exported = await _client.GetAsync("/api/lab-results/export/secrets");
        var report = JsonSerializer.Deserialize<SecretsExportReport>(
            await exported.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.NotNull(report);
        Assert.Equal(5, report.Summary.PassedCases);
        Assert.Equal(0, report.Summary.FailedCases);
        Assert.Equal(0, report.Summary.PendingCases);
        Assert.Equal(4, report.Summary.ImportedFindings);
        Assert.Equal(5, report.Results.Count);
        var falsePositive = Assert.Single(report.Results.Where(item => item.CaseId == "SECRET-FP-001"));
        Assert.True(falsePositive.Passed);
        Assert.Equal("False", falsePositive.Evidence!["detected"]);
    }

    [Fact]
    public async Task InvalidSecretsJson_IsRejected()
    {
        using var form = Form("{ invalid");
        var response = await _client.PostAsync("/api/lab-results/import-secrets", form);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static MultipartFormDataContent Form(string json)
    {
        var form = new MultipartFormDataContent();
        form.Add(new StringContent(json, Encoding.UTF8, "application/json"), "file", "gitleaks-results.json");
        return form;
    }

    private const string ValidGitleaksJson = """
    [
      {"RuleID":"lab-aws-access-key","Description":"AWS laboratory key","StartLine":2,"File":"fixtures/secrets/detectable-secrets.env","Fingerprint":"aws:2"},
      {"RuleID":"lab-github-token","Description":"GitHub laboratory token","StartLine":3,"File":"fixtures/secrets/detectable-secrets.env","Fingerprint":"github:3"},
      {"RuleID":"lab-password","Description":"Laboratory password","StartLine":4,"File":"fixtures/secrets/detectable-secrets.env","Fingerprint":"password:4"},
      {"RuleID":"lab-internal-key","Description":"Low-confidence laboratory key","StartLine":5,"File":"fixtures/secrets/detectable-secrets.env","Fingerprint":"internal:5"}
    ]
    """;
}
