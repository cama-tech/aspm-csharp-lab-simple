using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class ControlledCommandTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public ControlledCommandTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Theory]
    [InlineData("whoami")]
    [InlineData("pwd")]
    [InlineData("date -u")]
    public async Task AllowlistedCommand_IsExecuted(string command)
    {
        var response = await _client.GetAsync($"/api/diagnostic?command={Uri.EscapeDataString(command)}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(document.RootElement.GetProperty("executed").GetBoolean());
        Assert.Equal(command, document.RootElement.GetProperty("command").GetString());
        Assert.False(string.IsNullOrWhiteSpace(document.RootElement.GetProperty("output").GetString()));
    }

    [Theory]
    [InlineData("rm -rf /tmp/lab")]
    [InlineData("whoami; id")]
    [InlineData("pwd && date")]
    [InlineData("cat /etc/passwd")]
    public async Task NonAllowlistedCommand_IsRejected(string command)
    {
        var response = await _client.GetAsync($"/api/diagnostic?command={Uri.EscapeDataString(command)}");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(document.RootElement.GetProperty("executed").GetBoolean());
    }
}

