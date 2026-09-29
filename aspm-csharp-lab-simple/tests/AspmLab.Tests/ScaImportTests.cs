using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class ScaImportTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public ScaImportTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task ScaExport_WithoutImport_ListsExpectedCasesAsPending()
    {
        await _client.DeleteAsync("/api/lab-results");

        var exported = await _client.GetAsync("/api/lab-results/export/sca");
        Assert.Equal(HttpStatusCode.OK, exported.StatusCode);

        var report = JsonSerializer.Deserialize<ScaExportReport>(
            await exported.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        Assert.NotNull(report);
        Assert.Equal(6, report.Summary.ExpectedCases);
        Assert.Equal(0, report.Summary.PassedCases);
        Assert.Equal(0, report.Summary.FailedCases);
        Assert.Equal(6, report.Summary.PendingCases);
        Assert.Equal(0, report.Summary.ImportedFindings);
        Assert.Equal(6, report.Results.Count);
        Assert.All(report.Results, result =>
        {
            Assert.Equal("SCA-PENDING", result.Method);
            Assert.Null(result.Passed);
            Assert.Equal("pending", result.Evidence!["validationStatus"]);
            Assert.False(string.IsNullOrWhiteSpace(result.Evidence["package"]));
            Assert.False(string.IsNullOrWhiteSpace(result.Evidence["expectedVersion"]));
        });
    }

    [Fact]
    public async Task DotnetScaJson_IsImportedAndMappedToExpectedCases()
    {
        await _client.DeleteAsync("/api/lab-results");
        using var form = CreateScaForm(ValidScaJson);

        var response = await _client.PostAsync("/api/lab-results/import-sca", form);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var summary = await response.Content.ReadFromJsonAsync<ScaImportSummary>();
        Assert.NotNull(summary);
        Assert.Equal(1, summary.ProjectsScanned);
        Assert.Equal(5, summary.PackagesScanned);
        Assert.Equal(6, summary.Imported);
        Assert.Equal(6, summary.Mapped);
        Assert.Equal(0, summary.Unmapped);

        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results/sca");
        Assert.Equal(7, results!.Count);
        Assert.Contains(results, item => item.CaseId == "SCA-CRITICAL-001");
        Assert.Contains(results, item => item.CaseId == "SCA-CRITICAL-002");
        Assert.Contains(results, item => item.CaseId == "SCA-HIGH-001");
        Assert.Contains(results, item => item.CaseId == "SCA-LOW-001");
        Assert.Equal(2, results.Count(item => item.CaseId == "SCA-MULTI-001"));
        Assert.True(Assert.Single(results.Where(item => item.CaseId == "SCA-FP-001")).Passed);
        Assert.All(results.Where(item => item.Method == "SCA-IMPORT"), item =>
        {
            Assert.Equal("sca", item.Source);
            Assert.Equal("dotnet list package", item.Tool);
            Assert.True(item.Passed);
            Assert.NotNull(item.Evidence);
            Assert.Equal("True", item.Evidence!["detected"]);
            Assert.Equal("True", item.Evidence["versionMatches"]);
            Assert.False(string.IsNullOrWhiteSpace(item.Assertion));
        });
    }

    [Fact]
    public async Task ScaQueryAndExport_ContainOnlyScaResults()
    {
        await _client.DeleteAsync("/api/lab-results");
        using (var form = CreateScaForm(ValidScaJson))
        {
            var imported = await _client.PostAsync("/api/lab-results/import-sca", form);
            Assert.Equal(HttpStatusCode.OK, imported.StatusCode);
        }

        var nonSca = new ManualLabResult(
            "NEW-SAST-001",
            "SAST expected",
            "SAST observed",
            true,
            "MANUAL",
            "src/AspmLab/Program.cs",
            string.Empty,
            null,
            "Non-SCA control record");
        var created = await _client.PostAsJsonAsync("/api/lab-results", nonSca);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var all = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results");
        Assert.Equal(8, all!.Count);

        var scaOnly = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results/sca");
        Assert.Equal(7, scaOnly!.Count);
        Assert.All(scaOnly, result => Assert.StartsWith("SCA-", result.CaseId));

        var exported = await _client.GetAsync("/api/lab-results/export/sca");
        Assert.Equal(HttpStatusCode.OK, exported.StatusCode);
        Assert.Equal("application/json", exported.Content.Headers.ContentType?.MediaType);
        Assert.Contains(
            "aspm-sca-results.json",
            exported.Content.Headers.ContentDisposition?.FileName ?? string.Empty);

        var report = JsonSerializer.Deserialize<ScaExportReport>(
            await exported.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.NotNull(report);
        Assert.Equal(6, report.Summary.ExpectedCases);
        Assert.Equal(6, report.Summary.PassedCases);
        Assert.Equal(0, report.Summary.FailedCases);
        Assert.Equal(0, report.Summary.PendingCases);
        Assert.Equal(6, report.Summary.ImportedFindings);
        Assert.Equal(7, report.Results.Count);
        Assert.All(report.Results, result => Assert.Equal("sca", result.Source));
    }

    [Fact]
    public async Task MissingExpectedPackages_AreLoggedAsFailedScaResults()
    {
        await _client.DeleteAsync("/api/lab-results");
        const string json = """
        {
          "version": 1,
          "projects": [{
            "path": "src/AspmLab/AspmLab.csproj",
            "frameworks": [{
              "framework": "net8.0",
              "topLevelPackages": [{
                "id": "Newtonsoft.Json",
                "requestedVersion": "12.0.1",
                "resolvedVersion": "12.0.1",
                "vulnerabilities": [{
                  "severity": "High",
                  "advisoryurl": "https://example.invalid/newtonsoft"
                }]
              }]
            }]
          }]
        }
        """;
        using var form = CreateScaForm(json);
        var response = await _client.PostAsync("/api/lab-results/import-sca", form);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results/sca");
        Assert.Equal(6, results!.Count);
        Assert.True(Assert.Single(results.Where(item => item.CaseId == "SCA-HIGH-001")).Passed);

        var missingCritical = Assert.Single(results.Where(item => item.CaseId == "SCA-CRITICAL-002"));
        Assert.False(missingCritical.Passed);
        Assert.Equal("False", missingCritical.Evidence!["detected"]);
        Assert.NotNull(missingCritical.FailureReason);

        var incompleteMulti = Assert.Single(results.Where(item => item.CaseId == "SCA-MULTI-001"));
        Assert.False(incompleteMulti.Passed);
        Assert.Equal("0", incompleteMulti.Evidence!["detectedFindings"]);
    }

    [Fact]
    public async Task UnknownVulnerablePackage_IsImportedForManualReview()
    {
        await _client.DeleteAsync("/api/lab-results");
        const string json = """
        {
          "version": 1,
          "projects": [{
            "path": "fixtures/sca/Other.csproj",
            "frameworks": [{
              "framework": "net8.0",
              "topLevelPackages": [{
                "id": "Other.Package",
                "requestedVersion": "1.0.0",
                "resolvedVersion": "1.0.0",
                "vulnerabilities": [{
                  "severity": "Moderate",
                  "advisoryurl": "https://example.invalid/advisory"
                }]
              }]
            }]
          }]
        }
        """;
        using var form = CreateScaForm(json);

        var response = await _client.PostAsync("/api/lab-results/import-sca", form);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var result = Assert.Single((await _client.GetFromJsonAsync<List<LabExecutionResult>>(
            "/api/lab-results/sca"))!);
        Assert.Equal("SCA-UNMAPPED", result.CaseId);
        Assert.Null(result.Passed);
        Assert.Equal("Other.Package", result.Evidence!["package"]);
    }

    [Fact]
    public async Task InvalidScaJson_IsRejected()
    {
        using var form = CreateScaForm("{ invalid");
        var response = await _client.PostAsync("/api/lab-results/import-sca", form);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static MultipartFormDataContent CreateScaForm(string json)
    {
        var form = new MultipartFormDataContent();
        form.Add(new StringContent(json, Encoding.UTF8, "application/json"), "file", "sca-results.json");
        return form;
    }

    private const string ValidScaJson = """
    {
      "version": 1,
      "projects": [{
        "path": "src/AspmLab/AspmLab.csproj",
        "frameworks": [{
          "framework": "net8.0",
          "topLevelPackages": [
            {
              "id": "DNS",
              "requestedVersion": "6.1.0",
              "resolvedVersion": "6.1.0",
              "vulnerabilities": [{
                "severity": "Critical",
                "advisoryurl": "https://example.invalid/dns"
              }]
            },
            {
              "id": "EnumStringValues",
              "requestedVersion": "4.0.0",
              "resolvedVersion": "4.0.0",
              "vulnerabilities": [{
                "severity": "Low",
                "advisoryurl": "https://example.invalid/enum-string-values"
              }]
            },
            {
              "id": "Newtonsoft.Json",
              "requestedVersion": "12.0.1",
              "resolvedVersion": "12.0.1",
              "vulnerabilities": [{
                "severity": "High",
                "advisoryurl": "https://example.invalid/newtonsoft"
              }]
            },
            {
              "id": "System.Text.Encodings.Web",
              "requestedVersion": "4.7.0",
              "resolvedVersion": "4.7.0",
              "vulnerabilities": [{
                "severity": "Critical",
                "advisoryurl": "https://example.invalid/encodings"
              }]
            },
            {
              "id": "SixLabors.ImageSharp",
              "requestedVersion": "2.1.3",
              "resolvedVersion": "2.1.3",
              "vulnerabilities": [
                {
                  "severity": "Moderate",
                  "advisoryurl": "https://example.invalid/imagesharp-1"
                },
                {
                  "severity": "High",
                  "advisoryurl": "https://example.invalid/imagesharp-2"
                }
              ]
            }
          ],
          "transitivePackages": []
        }]
      }]
    }
    """;
}
