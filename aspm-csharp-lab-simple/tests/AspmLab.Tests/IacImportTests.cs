using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class IacImportTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    public IacImportTests(WebApplicationFactory<Program> factory) => _client = factory.CreateClient();

    [Fact]
    public async Task IacExport_WithoutImport_ListsFivePendingCases()
    {
        await _client.DeleteAsync("/api/lab-results");
        var response = await _client.GetAsync("/api/lab-results/export/iac");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("aspm-iac-results.json", response.Content.Headers.ContentDisposition?.FileName ?? string.Empty);
        var report = await ReadReport(response);
        Assert.Equal(5, report.Summary.ExpectedCases);
        Assert.Equal(0, report.Summary.PassedCases);
        Assert.Equal(0, report.Summary.FailedCases);
        Assert.Equal(5, report.Summary.PendingCases);
        Assert.Equal(0, report.Summary.ImportedFindings);
        Assert.All(report.Results, item => Assert.Equal("IAC-PENDING", item.Method));
    }

    [Fact]
    public async Task CheckovJson_MapsFourFindingsAndApprovesNegativeControl()
    {
        await _client.DeleteAsync("/api/lab-results");
        using var form = Form(ValidCheckovJson);
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-iac", form)).StatusCode);

        var report = await ReadReport(await _client.GetAsync("/api/lab-results/export/iac"));
        Assert.Equal(5, report.Summary.ExpectedCases);
        Assert.Equal(5, report.Summary.PassedCases);
        Assert.Equal(0, report.Summary.FailedCases);
        Assert.Equal(0, report.Summary.PendingCases);
        Assert.Equal(4, report.Summary.ImportedFindings);
        Assert.Equal(0, report.Summary.UnmappedFindings);
        var falsePositive = Assert.Single(report.Results.Where(item => item.CaseId == "IAC-FP-001"));
        Assert.True(falsePositive.Passed);
        Assert.Equal("False", falsePositive.Evidence!["detected"]);
    }

    [Fact]
    public async Task MissingExpectedResource_IsRecordedAsFailed()
    {
        await _client.DeleteAsync("/api/lab-results");
        using var form = Form(ValidCheckovJson.Replace("aws_vpc.lab", "aws_vpc.other"));
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-iac", form)).StatusCode);
        var report = await ReadReport(await _client.GetAsync("/api/lab-results/export/iac"));
        var missing = Assert.Single(report.Results.Where(item => item.CaseId == "IAC-MEDIUM-001"));
        Assert.False(missing.Passed);
        Assert.NotNull(missing.FailureReason);
        Assert.Contains(report.Results, item => item.CaseId == "IAC-UNMAPPED");
    }

    [Fact]
    public async Task LocalhostReportedAsPublicExposure_FailsFalsePositiveControl()
    {
        await _client.DeleteAsync("/api/lab-results");
        var json = ValidCheckovJson.Replace("]}}", ",{" +
            "\"check_id\":\"CKV_LAB_FP\",\"check_name\":\"Public Internet exposure\"," +
            "\"resource\":\"aws_security_group.localhost_service\",\"file_path\":\"/infra/false-positive.tf\"," +
            "\"file_line_range\":[1,12]}]}}");
        using var form = Form(json);
        Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-iac", form)).StatusCode);
        var report = await ReadReport(await _client.GetAsync("/api/lab-results/export/iac"));
        Assert.False(Assert.Single(report.Results.Where(item => item.CaseId == "IAC-FP-001")).Passed);
    }

    [Fact]
    public async Task IacQueryDoesNotReturnOtherReviewResults()
    {
        await _client.DeleteAsync("/api/lab-results");
        using (var form = Form(ValidCheckovJson))
            Assert.Equal(HttpStatusCode.OK, (await _client.PostAsync("/api/lab-results/import-iac", form)).StatusCode);
        var nonIac = new ManualLabResult("SECRET-LOW-001", "secret", "secret", true,
            "MANUAL", "file", "[REDACTED]", null, "Non-IaC control");
        Assert.Equal(HttpStatusCode.Created, (await _client.PostAsJsonAsync("/api/lab-results", nonIac)).StatusCode);
        var results = await _client.GetFromJsonAsync<List<LabExecutionResult>>("/api/lab-results/iac");
        Assert.NotNull(results);
        Assert.All(results, item => Assert.StartsWith("IAC-", item.CaseId));
    }

    [Fact]
    public async Task InvalidCheckovJson_IsRejected()
    {
        using var form = Form("{ invalid");
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsync("/api/lab-results/import-iac", form)).StatusCode);
    }

    private static MultipartFormDataContent Form(string json)
    {
        var form = new MultipartFormDataContent();
        form.Add(new StringContent(json, Encoding.UTF8, "application/json"), "file", "checkov-results.json");
        return form;
    }

    private static async Task<IacExportReport> ReadReport(HttpResponseMessage response) =>
        JsonSerializer.Deserialize<IacExportReport>(await response.Content.ReadAsStringAsync(),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

    private const string ValidCheckovJson = """
    {"results":{"failed_checks":[
      {"check_id":"CKV_LAB_CRITICAL","check_name":"Database port open to the Internet","resource":"aws_security_group.database","file_path":"/infra/main.tf","file_line_range":[25,37]},
      {"check_id":"CKV_LAB_HIGH","check_name":"S3 public access block disabled","resource":"aws_s3_bucket_public_access_block.aspm_lab","file_path":"/infra/main.tf","file_line_range":[17,23]},
      {"check_id":"CKV_LAB_MEDIUM","check_name":"VPC flow logs missing","resource":"aws_vpc.lab","file_path":"/infra/main.tf","file_line_range":[50,54]},
      {"check_id":"CKV_LAB_LOW","check_name":"Unrestricted egress","resource":"aws_security_group_rule.all_egress","file_path":"/infra/main.tf","file_line_range":[57,65]}
    ]}}
    """;
}
