using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AspmLab.Tests;

public class DastEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public DastEndpointTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    [Fact]
    public async Task Search_ReflectsUnencodedInput()
    {
        const string payload = "<script>labOnly()</script>";
        var response = await _client.GetAsync($"/api/search?q={Uri.EscapeDataString(payload)}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(payload, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Redirect_AcceptsExternalDestination()
    {
        var response = await _client.GetAsync("/api/redirect?url=https%3A%2F%2Fexample.invalid");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("example.invalid", response.Headers.Location?.Host);
    }

    [Fact]
    public async Task Root_DoesNotAddExpectedSecurityHeaders()
    {
        var response = await _client.GetAsync("/");
        Assert.False(response.Headers.Contains("Content-Security-Policy"));
        Assert.False(response.Headers.Contains("X-Frame-Options"));
    }
}
