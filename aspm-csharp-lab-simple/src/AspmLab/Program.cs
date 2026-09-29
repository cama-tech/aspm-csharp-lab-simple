using System.Diagnostics;
using System.Net;
using System.Text;
using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSingleton<LabResultStore>();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new()
    {
        Title = "ASPM C# Vulnerable Laboratory",
        Version = "v1",
        Description = "API deliberadamente vulnerable para pruebas locales y controladas. No desplegar en producción."
    });
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "ASPM Laboratory v1");
    options.RoutePrefix = "swagger";
    options.DocumentTitle = "ASPM C# Laboratory";
});

var automaticCases = new Dictionary<string, (string CaseId, string Expected)>(StringComparer.OrdinalIgnoreCase)
{
    ["/api/diagnostic"] = ("NEW-SAST-001", "Allowed commands execute; every other command returns HTTP 400."),
    ["/api/search"] = ("BASELINE-SAST-001", "Input is reflected in HTML without output encoding."),
    ["/api/redirect"] = ("BASELINE-SAST-002", "An external destination produces HTTP 302."),
    ["/api/file"] = ("BASELINE-SAST-003", "A relative path can leave the lab-data directory."),
    ["/api/session/audit"] = ("MEDIUM-SAST-001", "Email and fictitious token are written to the application log."),
    ["/api/legacy/import"] = ("LOW-SAST-001", "The payload is parsed with TypeNameHandling.All."),
    ["/api/orders/quote"] = ("BUSINESS-HIGH-002", "The client-controlled total is accepted."),
    ["/api/transfers"] = ("BUSINESS-MEDIUM-001", "A duplicated transfer is accepted again."),
    ["/api/limits/check"] = ("BUSINESS-MEDIUM-002", "The limit is evaluated per operation."),
    ["/api/public-id"] = ("SAST-FP-001", "The public fictitious identifier must be classified as a false positive.")
};

app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value ?? string.Empty;
    if (path.StartsWith("/api/lab-results", StringComparison.OrdinalIgnoreCase))
    {
        await next();
        return;
    }

    var startedAt = DateTimeOffset.UtcNow;
    var started = Stopwatch.GetTimestamp();
    context.Request.EnableBuffering();
    var requestBody = string.Empty;
    if (context.Request.ContentLength > 0)
    {
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
        requestBody = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;
    }

    var originalBody = context.Response.Body;
    await using var responseBuffer = new MemoryStream();
    context.Response.Body = responseBuffer;
    await next();
    var completedAt = DateTimeOffset.UtcNow;
    responseBuffer.Position = 0;
    var responseBody = await new StreamReader(responseBuffer, Encoding.UTF8, leaveOpen: true).ReadToEndAsync();
    responseBuffer.Position = 0;
    await responseBuffer.CopyToAsync(originalBody);
    context.Response.Body = originalBody;

    var match = automaticCases.FirstOrDefault(item =>
        path.Equals(item.Key, StringComparison.OrdinalIgnoreCase) ||
        (item.Key == "/api/orders/{id}" && path.StartsWith("/api/orders/", StringComparison.OrdinalIgnoreCase)));

    var caseId = match.Value.CaseId;
    var expected = match.Value.Expected;

    if (path.StartsWith("/api/orders/", StringComparison.OrdinalIgnoreCase) &&
        path.EndsWith("/approve", StringComparison.OrdinalIgnoreCase))
    {
        caseId = "BUSINESS-CRITICAL-001";
        expected = "A caller-supplied role can approve the order.";
    }
    else if (path.StartsWith("/api/orders/", StringComparison.OrdinalIgnoreCase) &&
             !path.EndsWith("/quote", StringComparison.OrdinalIgnoreCase))
    {
        caseId = "BUSINESS-HIGH-001";
        expected = "A user can read an order owned by another user.";
    }

    if (string.IsNullOrWhiteSpace(caseId)) return;

    var evaluation = LabRuntimeEvaluator.Evaluate(
        caseId,
        context.Request,
        context.Response,
        requestBody,
        responseBody,
        app.Environment.ContentRootPath);
    var store = context.RequestServices.GetRequiredService<LabResultStore>();
    store.Add(new LabExecutionResult(
        Guid.NewGuid(),
        DateTimeOffset.UtcNow,
        caseId,
        context.Request.Method,
        path,
        string.IsNullOrWhiteSpace(requestBody)
            ? context.Request.QueryString.Value ?? string.Empty
            : requestBody,
        expected,
        evaluation.Observed,
        evaluation.Passed,
        Stopwatch.GetElapsedTime(started).TotalMilliseconds,
        "Automatically evaluated and recorded by the laboratory.",
        Source: "runtime",
        TestRunId: store.TestRunId,
        ApplicationVersion: typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown",
        Environment: app.Environment.EnvironmentName,
        StartedAtUtc: startedAt,
        CompletedAtUtc: completedAt,
        ExpectedStatusCode: evaluation.ExpectedStatusCode,
        ActualStatusCode: context.Response.StatusCode,
        Assertion: evaluation.Assertion,
        FailureReason: evaluation.FailureReason,
        Evidence: evaluation.Evidence));
});

// ASPM LAB ONLY. This application deliberately contains detectable weaknesses.
// Run it only on localhost and never reuse this code in a real application.

app.MapGet("/", () => Results.Ok(new
{
    application = "ASPM C# Laboratory",
    warning = "Contains intentional vulnerabilities for controlled testing",
    swagger = "/swagger",
    endpoints = new[] { "/health", "/api/search?q=test", "/api/redirect?url=/", "/api/file?name=sample.txt", "/api/lab-results" }
}));

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapGet("/api/lab-results", (LabResultStore store) => Results.Ok(store.GetAll()));

app.MapGet("/api/lab-results/sca", (LabResultStore store) => Results.Ok(store.GetSca()));
app.MapGet("/api/lab-results/sast", (LabResultStore store) => Results.Ok(store.GetSast()));
app.MapGet("/api/lab-results/secrets", (LabResultStore store) => Results.Ok(store.GetSecrets()));
app.MapGet("/api/lab-results/sbom", (LabResultStore store) => Results.Ok(store.GetSbom()));
app.MapGet("/api/lab-results/iac", (LabResultStore store) => Results.Ok(store.GetIac()));
app.MapGet("/api/lab-results/container", (LabResultStore store) => Results.Ok(store.GetContainer()));
app.MapGet("/api/lab-results/dast", (LabResultStore store) => Results.Ok(store.GetDast()));

app.MapGet("/api/lab-results/export", (LabResultStore store) =>
{
    var json = System.Text.Json.JsonSerializer.Serialize(store.GetAll(), new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true
    });
    return Results.File(
        Encoding.UTF8.GetBytes(json),
        "application/json",
        "aspm-lab-results.json");
});

app.MapGet("/api/lab-results/export/sca", (LabResultStore store) =>
{
    var report = ScaExportReport.Create(store.GetSca(), store.TestRunId);
    var json = System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true
    });
    return Results.File(
        Encoding.UTF8.GetBytes(json),
        "application/json",
        "aspm-sca-results.json");
});

app.MapGet("/api/lab-results/export/sast", (LabResultStore store) =>
{
    var report = SastExportReport.Create(store.GetSast(), store.TestRunId);
    var json = System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true
    });
    return Results.File(Encoding.UTF8.GetBytes(json), "application/json", "aspm-sast-results.json");
});

app.MapGet("/api/lab-results/export/secrets", (LabResultStore store) =>
{
    var report = SecretsExportReport.Create(store.GetSecrets(), store.TestRunId);
    var json = System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true
    });
    return Results.File(Encoding.UTF8.GetBytes(json), "application/json", "aspm-secrets-results.json");
});

app.MapGet("/api/lab-results/export/sbom", (LabResultStore store) =>
{
    var report = SbomExportReport.Create(store.GetSbom(), store.TestRunId);
    var json = System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true
    });
    return Results.File(Encoding.UTF8.GetBytes(json), "application/json", "aspm-sbom-results.json");
});

app.MapGet("/api/lab-results/export/iac", (LabResultStore store) =>
{
    var report = IacExportReport.Create(store.GetIac(), store.TestRunId);
    var json = System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true
    });
    return Results.File(Encoding.UTF8.GetBytes(json), "application/json", "aspm-iac-results.json");
});

app.MapGet("/api/lab-results/export/container", (LabResultStore store) =>
{
    var report = ContainerExportReport.Create(store.GetContainer(), store.TestRunId);
    var json = System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true
    });
    return Results.File(Encoding.UTF8.GetBytes(json), "application/json", "aspm-container-results.json");
});

app.MapGet("/api/lab-results/export/dast", (LabResultStore store) =>
{
    var report = DastExportReport.Create(store.GetDast(), store.TestRunId);
    var json = System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true
    });
    return Results.File(Encoding.UTF8.GetBytes(json), "application/json", "aspm-dast-results.json");
});

app.MapPost("/api/lab-results", (ManualLabResult result, LabResultStore store) =>
{
    var saved = new LabExecutionResult(
        Guid.NewGuid(),
        DateTimeOffset.UtcNow,
        result.CaseId,
        result.Method ?? "MANUAL",
        result.Path ?? string.Empty,
        result.Input ?? string.Empty,
        result.Expected,
        result.Observed,
        result.Passed,
        result.DurationMilliseconds,
        result.Notes ?? "Manually recorded from Swagger.",
        result.Tool,
        result.ToolVersion,
        result.RuleId,
        result.Severity,
        result.File,
        result.Line,
        result.Message,
        "manual");
    store.Add(saved);
    return Results.Created($"/api/lab-results/{saved.Id}", saved);
});

app.MapPost("/api/lab-results/import-sast", async (IFormFile file, LabResultStore store) =>
{
    if (file.Length == 0)
        return Results.BadRequest(new { message = "The SARIF file is empty." });

    try
    {
        await using var stream = file.OpenReadStream();
        var summary = await SarifImporter.ImportAsync(stream, store);
        return Results.Ok(summary);
    }
    catch (System.Text.Json.JsonException exception)
    {
        return Results.BadRequest(new { message = "The file is not valid SARIF JSON.", detail = exception.Message });
    }
}).DisableAntiforgery();

app.MapPost("/api/lab-results/import-sca", async (IFormFile file, LabResultStore store) =>
{
    if (file.Length == 0)
        return Results.BadRequest(new { message = "The SCA JSON file is empty." });

    try
    {
        await using var stream = file.OpenReadStream();
        var summary = await ScaImporter.ImportAsync(stream, store);
        return Results.Ok(summary);
    }
    catch (System.Text.Json.JsonException exception)
    {
        return Results.BadRequest(new
        {
            message = "The file is not valid dotnet list package JSON.",
            detail = exception.Message
        });
    }
}).DisableAntiforgery();

app.MapPost("/api/lab-results/import-secrets", async (IFormFile file, LabResultStore store) =>
{
    if (file.Length == 0)
        return Results.BadRequest(new { message = "The Gitleaks JSON file is empty." });
    try
    {
        await using var stream = file.OpenReadStream();
        return Results.Ok(await SecretsImporter.ImportAsync(stream, store));
    }
    catch (System.Text.Json.JsonException exception)
    {
        return Results.BadRequest(new { message = "The file is not valid Gitleaks JSON.", detail = exception.Message });
    }
}).DisableAntiforgery();

app.MapPost("/api/lab-results/import-sbom", async (IFormFile file, LabResultStore store) =>
{
    if (file.Length == 0)
        return Results.BadRequest(new { message = "The CycloneDX JSON file is empty." });
    try
    {
        await using var stream = file.OpenReadStream();
        return Results.Ok(await SbomImporter.ImportAsync(stream, store));
    }
    catch (System.Text.Json.JsonException exception)
    {
        return Results.BadRequest(new { message = "The file is not valid CycloneDX JSON.", detail = exception.Message });
    }
}).DisableAntiforgery();

app.MapPost("/api/lab-results/import-iac", async (IFormFile file, LabResultStore store) =>
{
    if (file.Length == 0)
        return Results.BadRequest(new { message = "The Checkov JSON file is empty." });
    try
    {
        await using var stream = file.OpenReadStream();
        return Results.Ok(await IacImporter.ImportAsync(stream, store));
    }
    catch (System.Text.Json.JsonException exception)
    {
        return Results.BadRequest(new { message = "The file is not valid Checkov JSON.", detail = exception.Message });
    }
}).DisableAntiforgery();

app.MapPost("/api/lab-results/import-container", async (IFormFile file, LabResultStore store) =>
{
    if (file.Length == 0)
        return Results.BadRequest(new { message = "The Trivy JSON file is empty." });
    try
    {
        await using var stream = file.OpenReadStream();
        return Results.Ok(await ContainerImporter.ImportAsync(stream, store));
    }
    catch (System.Text.Json.JsonException exception)
    {
        return Results.BadRequest(new { message = "The file is not valid Trivy JSON.", detail = exception.Message });
    }
}).DisableAntiforgery();

app.MapPost("/api/lab-results/import-dast", async (IFormFile file, LabResultStore store) =>
{
    if (file.Length == 0)
        return Results.BadRequest(new { message = "The OWASP ZAP JSON file is empty." });
    try
    {
        await using var stream = file.OpenReadStream();
        return Results.Ok(await DastImporter.ImportAsync(stream, store));
    }
    catch (System.Text.Json.JsonException exception)
    {
        return Results.BadRequest(new { message = "The file is not valid OWASP ZAP JSON.", detail = exception.Message });
    }
}).DisableAntiforgery();

app.MapDelete("/api/lab-results", (LabResultStore store) =>
{
    store.Clear();
    return Results.NoContent();
});

var orders = new Dictionary<int, LabOrder>
{
    [1001] = new(1001, "alice", 125.50m, "Pending"),
    [1002] = new(1002, "bob", 980.00m, "Pending")
};

var processedTransfers = new List<LabTransfer>();

// BASELINE-SAST-001: reflected input without output encoding.
app.MapGet("/api/search", (string? q) =>
{
    var html = $"<html><body>Search result: {q}</body></html>";
    return Results.Content(html, "text/html");
});

// BASELINE-SAST-002: unvalidated redirect.
app.MapGet("/api/redirect", (string? url) => Results.Redirect(url ?? "/"));

// BASELINE-SAST-003: user-controlled path.
app.MapGet("/api/file", (string? name) =>
{
    var labRoot = Path.Combine(app.Environment.ContentRootPath, "lab-data");
    var requested = Path.Combine(labRoot, name ?? "sample.txt");
    return File.Exists(requested)
        ? Results.Text(File.ReadAllText(requested))
        : Results.NotFound();
});

// NEW-SAST-001: controlled command-execution case for this isolated laboratory.
// The shell sink remains visible to SAST, but only exact allowlisted commands can reach it.
app.MapGet("/api/diagnostic", (string? command, IConfiguration configuration) =>
{
    if (!configuration.GetValue<bool>("Lab:EnableControlledCommandEndpoint"))
        return Results.NotFound();

    var requestedCommand = (command ?? string.Empty).Trim();
    var allowedCommands = new HashSet<string>(StringComparer.Ordinal)
    {
        "whoami",
        "pwd",
        "date -u"
    };

    if (!allowedCommands.Contains(requestedCommand))
    {
        return Results.BadRequest(new
        {
            executed = false,
            message = "Command rejected. Allowed values: whoami, pwd, date -u"
        });
    }

    var commandSpec = OperatingSystem.IsWindows()
        ? requestedCommand switch
        {
            "whoami" => (FileName: "whoami.exe", Arguments: Array.Empty<string>()),
            "pwd" => (FileName: "cmd.exe", Arguments: new[] { "/d", "/c", "cd" }),
            "date -u" => (FileName: "powershell.exe", Arguments: new[]
            {
                "-NoProfile", "-NonInteractive", "-Command",
                "(Get-Date).ToUniversalTime().ToString('u')"
            }),
            _ => throw new InvalidOperationException("Command was not allowlisted.")
        }
        : (FileName: "/bin/sh", Arguments: new[] { "-c", requestedCommand });

    var startInfo = new ProcessStartInfo(commandSpec.FileName)
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false
    };
    foreach (var argument in commandSpec.Arguments)
        startInfo.ArgumentList.Add(argument);
    using var process = Process.Start(startInfo);
    var output = process?.StandardOutput.ReadToEnd() ?? string.Empty;
    var error = process?.StandardError.ReadToEnd() ?? string.Empty;
    process?.WaitForExit();
    return Results.Ok(new
    {
        executed = process?.ExitCode == 0,
        command = requestedCommand,
        output = output.Trim(),
        error = error.Trim(),
        exitCode = process?.ExitCode
    });
});

// MEDIUM-SAST-001: sensitive data is written to application logs.
app.MapPost("/api/session/audit", (SessionAudit audit, ILogger<Program> logger) =>
{
    logger.LogInformation("Login audit for {Email} with token {Token}", audit.Email, audit.Token);
    return Results.Ok(new
    {
        recorded = true,
        logWritten = true,
        email = audit.Email,
        tokenMasked = MaskValue(audit.Token)
    });
});

// LOW-SAST-001: untrusted JSON type metadata is accepted in a lab-only endpoint.
app.MapPost("/api/legacy/import", (string payload) =>
{
    var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
    var result = JsonConvert.DeserializeObject(payload, settings);
    return Results.Ok(new
    {
        parsedType = result?.GetType().Name ?? "null",
        typeNameHandling = settings.TypeNameHandling.ToString()
    });
});

// BUSINESS-HIGH-001: IDOR/BOLA. The supplied user is not checked against the owner.
app.MapGet("/api/orders/{id:int}", (int id, string user) =>
    orders.TryGetValue(id, out var order)
        ? Results.Ok(order)
        : Results.NotFound());

// BUSINESS-HIGH-002: the server trusts a total controlled by the client.
app.MapPost("/api/orders/quote", (QuoteRequest quote) =>
    Results.Ok(new
    {
        acceptedTotal = quote.ClientTotal,
        expectedTotal = quote.UnitPrice * quote.Quantity
    }));

// BUSINESS-CRITICAL-001: role and workflow state are trusted from the request.
app.MapPost("/api/orders/{id:int}/approve", (int id, string role) =>
{
    if (!orders.TryGetValue(id, out var order)) return Results.NotFound();
    orders[id] = order with { Status = "Approved" };
    return Results.Ok(new { id, approved = true, suppliedRole = role });
});

// BUSINESS-MEDIUM-001: no idempotency key is required; duplicate transfers are accepted.
app.MapPost("/api/transfers", (LabTransfer transfer) =>
{
    processedTransfers.Add(transfer);
    return Results.Created($"/api/transfers/{processedTransfers.Count}", new
    {
        sequence = processedTransfers.Count,
        transfer
    });
});

// BUSINESS-MEDIUM-002: limit is checked per operation, not cumulatively per user/day.
app.MapPost("/api/limits/check", (LimitRequest request) =>
    Results.Ok(new { allowed = request.Amount <= 1000m, request.User, request.Amount }));

// SECRET-FP-001: a public documentation identifier that resembles a token.
const string PublicDocumentationId = "ghp_000000000000000000000000000000000000";
app.MapGet("/api/public-id", () => Results.Ok(new { id = PublicDocumentationId }));

app.Run();

static string MaskValue(string value)
{
    if (string.IsNullOrEmpty(value)) return string.Empty;
    return value.Length <= 4 ? new string('*', value.Length) : $"{value[..2]}***{value[^2..]}";
}

public record LabOrder(int Id, string Owner, decimal Amount, string Status);
public record SessionAudit(string Email, string Token);
public record QuoteRequest(decimal UnitPrice, int Quantity, decimal ClientTotal);
public record LabTransfer(string User, string Destination, decimal Amount, string Reference);
public record LimitRequest(string User, decimal Amount);
public record ManualLabResult(
    string CaseId,
    string Expected,
    string Observed,
    bool? Passed,
    string? Method,
    string? Path,
    string? Input,
    double? DurationMilliseconds,
    string? Notes,
    string? Tool = null,
    string? ToolVersion = null,
    string? RuleId = null,
    string? Severity = null,
    string? File = null,
    int? Line = null,
    string? Message = null);
public record LabExecutionResult(
    Guid Id,
    DateTimeOffset TimestampUtc,
    string CaseId,
    string Method,
    string Path,
    string Input,
    string Expected,
    string Observed,
    bool? Passed,
    double? DurationMilliseconds,
    string Notes,
    string? Tool = null,
    string? ToolVersion = null,
    string? RuleId = null,
    string? Severity = null,
    string? File = null,
    int? Line = null,
    string? Message = null,
    string Source = "runtime",
    Guid? TestRunId = null,
    string? ApplicationVersion = null,
    string? Environment = null,
    DateTimeOffset? StartedAtUtc = null,
    DateTimeOffset? CompletedAtUtc = null,
    int? ExpectedStatusCode = null,
    int? ActualStatusCode = null,
    string? Assertion = null,
    string? FailureReason = null,
    IReadOnlyDictionary<string, string?>? Evidence = null);

public sealed class LabResultStore
{
    private readonly object _sync = new();
    private readonly List<LabExecutionResult> _results = new();
    public Guid TestRunId { get; private set; } = Guid.NewGuid();

    public void Add(LabExecutionResult result)
    {
        lock (_sync) _results.Add(result);
    }

    public IReadOnlyList<LabExecutionResult> GetAll()
    {
        lock (_sync) return _results.OrderBy(result => result.TimestampUtc).ToList();
    }

    public IReadOnlyList<LabExecutionResult> GetSca()
    {
        lock (_sync)
        {
            return _results
                .Where(result =>
                    result.Source.Equals("sca", StringComparison.OrdinalIgnoreCase) ||
                    result.CaseId.StartsWith("SCA-", StringComparison.OrdinalIgnoreCase))
                .OrderBy(result => result.TimestampUtc)
                .ToList();
        }
    }

    public IReadOnlyList<LabExecutionResult> GetSast()
    {
        lock (_sync)
        {
            return _results
                .Where(result => result.Source.Equals("sarif", StringComparison.OrdinalIgnoreCase) ||
                                 result.Source.Equals("sast", StringComparison.OrdinalIgnoreCase) ||
                                 result.CaseId.Contains("SAST-", StringComparison.OrdinalIgnoreCase))
                .OrderBy(result => result.TimestampUtc)
                .ToList();
        }
    }

    public IReadOnlyList<LabExecutionResult> GetSecrets()
    {
        lock (_sync)
        {
            return _results
                .Where(result => result.Source.Equals("secrets", StringComparison.OrdinalIgnoreCase) ||
                                 result.CaseId.StartsWith("SECRET-", StringComparison.OrdinalIgnoreCase))
                .OrderBy(result => result.TimestampUtc)
                .ToList();
        }
    }

    public IReadOnlyList<LabExecutionResult> GetSbom()
    {
        lock (_sync)
        {
            return _results
                .Where(result => result.Source.Equals("sbom", StringComparison.OrdinalIgnoreCase) ||
                                 result.CaseId.StartsWith("SBOM-", StringComparison.OrdinalIgnoreCase))
                .OrderBy(result => result.TimestampUtc)
                .ToList();
        }
    }

    public IReadOnlyList<LabExecutionResult> GetIac()
    {
        lock (_sync)
        {
            return _results
                .Where(result => result.Source.Equals("iac", StringComparison.OrdinalIgnoreCase) ||
                                 result.CaseId.StartsWith("IAC-", StringComparison.OrdinalIgnoreCase))
                .OrderBy(result => result.TimestampUtc)
                .ToList();
        }
    }

    public IReadOnlyList<LabExecutionResult> GetContainer()
    {
        lock (_sync)
        {
            return _results
                .Where(result => result.Source.Equals("container", StringComparison.OrdinalIgnoreCase) ||
                                 result.CaseId.StartsWith("CONTAINER-", StringComparison.OrdinalIgnoreCase))
                .OrderBy(result => result.TimestampUtc)
                .ToList();
        }
    }

    public IReadOnlyList<LabExecutionResult> GetDast()
    {
        lock (_sync)
        {
            return _results
                .Where(result => result.Source.Equals("dast", StringComparison.OrdinalIgnoreCase) ||
                                 result.CaseId.StartsWith("DAST-", StringComparison.OrdinalIgnoreCase))
                .OrderBy(result => result.TimestampUtc)
                .ToList();
        }
    }

    public void Clear()
    {
        lock (_sync)
        {
            _results.Clear();
            TestRunId = Guid.NewGuid();
        }
    }
}

public sealed record RuntimeEvaluation(
    bool Passed,
    string Observed,
    int ExpectedStatusCode,
    string Assertion,
    string? FailureReason,
    IReadOnlyDictionary<string, string?> Evidence);

public static class LabRuntimeEvaluator
{
    public static RuntimeEvaluation Evaluate(
        string caseId,
        HttpRequest request,
        HttpResponse response,
        string requestBody,
        string responseBody,
        string contentRoot)
    {
        var evidence = new Dictionary<string, string?>();
        var expectedStatus = StatusCodes.Status200OK;
        var assertion = string.Empty;
        var passed = false;

        switch (caseId)
        {
            case "NEW-SAST-001":
                var command = request.Query["command"].ToString();
                var allowed = command is "whoami" or "pwd" or "date -u";
                expectedStatus = allowed ? StatusCodes.Status200OK : StatusCodes.Status400BadRequest;
                var executed = ReadBoolean(responseBody, "executed");
                passed = response.StatusCode == expectedStatus && executed == allowed;
                assertion = allowed
                    ? "An allowlisted command returns HTTP 200 and executed=true."
                    : "A non-allowlisted command returns HTTP 400 and executed=false.";
                evidence["command"] = command;
                evidence["allowlisted"] = allowed.ToString();
                evidence["executed"] = executed?.ToString();
                evidence["outputPresent"] = (!string.IsNullOrWhiteSpace(ReadString(responseBody, "output"))).ToString();
                break;

            case "BASELINE-SAST-001":
                var query = request.Query["q"].ToString();
                assertion = "The response contains the exact input without HTML encoding.";
                passed = response.StatusCode == expectedStatus && responseBody.Contains(query, StringComparison.Ordinal);
                evidence["submittedText"] = query;
                evidence["reflectedWithoutEncoding"] = responseBody.Contains(query, StringComparison.Ordinal).ToString();
                break;

            case "BASELINE-SAST-002":
                expectedStatus = StatusCodes.Status302Found;
                var destination = request.Query["url"].ToString();
                var location = response.Headers.Location.ToString();
                assertion = "The application redirects to the external destination supplied by the client.";
                passed = response.StatusCode == expectedStatus && location == destination;
                evidence["requestedDestination"] = destination;
                evidence["location"] = location;
                break;

            case "BASELINE-SAST-003":
                var name = request.Query["name"].ToString();
                var labRoot = Path.GetFullPath(Path.Combine(contentRoot, "lab-data"));
                var resolved = Path.GetFullPath(Path.Combine(labRoot, name));
                var escaped = !resolved.StartsWith(labRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal);
                assertion = "The resolved user-controlled path leaves the lab-data directory and is read successfully.";
                passed = response.StatusCode == expectedStatus && escaped;
                evidence["requestedName"] = name;
                evidence["labRoot"] = labRoot;
                evidence["resolvedPath"] = resolved;
                evidence["escapedLabRoot"] = escaped.ToString();
                evidence["responseBodyPresent"] = (!string.IsNullOrWhiteSpace(responseBody)).ToString();
                break;

            case "MEDIUM-SAST-001":
                assertion = "The endpoint invokes the vulnerable log statement and confirms it in the response.";
                var logWritten = ReadBoolean(responseBody, "logWritten") == true;
                passed = response.StatusCode == expectedStatus && logWritten;
                evidence["logWritten"] = logWritten.ToString();
                evidence["email"] = ReadString(responseBody, "email");
                evidence["tokenMasked"] = ReadString(responseBody, "tokenMasked");
                break;

            case "LOW-SAST-001":
                assertion = "The response confirms that Newtonsoft.Json used TypeNameHandling.All.";
                var handling = ReadString(responseBody, "typeNameHandling");
                passed = response.StatusCode == expectedStatus && handling == "All";
                evidence["typeNameHandling"] = handling;
                evidence["parsedType"] = ReadString(responseBody, "parsedType");
                break;

            case "SAST-FP-001":
                assertion = "The endpoint exposes the documented fictitious public identifier; SAST false-positive classification remains external.";
                var identifier = ReadString(responseBody, "id");
                passed = response.StatusCode == expectedStatus && identifier == "ghp_000000000000000000000000000000000000";
                evidence["publicFictitiousIdentifierPresent"] = passed.ToString();
                evidence["sastClassification"] = "Pending external scanner review";
                break;

            default:
                assertion = "The intentionally vulnerable business endpoint returned a successful response.";
                passed = response.StatusCode is >= 200 and < 300;
                evidence["responseBodyPresent"] = (!string.IsNullOrWhiteSpace(responseBody)).ToString();
                break;
        }

        var observed = $"HTTP {response.StatusCode}; assertion={(passed ? "passed" : "failed")}";
        return new RuntimeEvaluation(
            passed,
            observed,
            expectedStatus,
            assertion,
            passed ? null : $"Expected HTTP {expectedStatus} and the case-specific assertion to pass.",
            evidence);
    }

    private static bool? ReadBoolean(string json, string property)
    {
        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty(property, out var value) &&
                   value.ValueKind is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False
                ? value.GetBoolean()
                : null;
        }
        catch (System.Text.Json.JsonException) { return null; }
    }

    private static string? ReadString(string json, string property)
    {
        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty(property, out var value) ? value.GetString() : null;
        }
        catch (System.Text.Json.JsonException) { return null; }
    }
}
public partial class Program { }
