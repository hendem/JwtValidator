using System.Net;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator.Tests;

public sealed class ValidateCommandTests : IDisposable
{
    private readonly RSA _rsa = TestTokens.NewRsa();
    private readonly List<string> _tempFiles = [];
    private readonly StringWriter _output = new();
    private readonly StringWriter _error = new();

    public void Dispose()
    {
        _rsa.Dispose();
        foreach (var file in _tempFiles)
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task JwtFileWithTrailingNewline_IsValid()
    {
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256);
        var options = new Options
        {
            JwtFile = WriteTempFile(jwt + "\r\n"),
            RsaKeyFile = WriteTempFile(_rsa.ExportSubjectPublicKeyInfoPem()),
        };

        var exitCode = await RunAsync(options);

        Assert.Equal(ExitCodes.Valid, exitCode);
        Assert.Contains("Result: token is valid", _output.ToString());
    }

    [Fact]
    public async Task JwksFromUrl_IsValid()
    {
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(_rsa) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256);
        var jwks = TestTokens.Jwks(TestTokens.RsaJwk(_rsa, "k1"));
        using var httpClient = new HttpClient(new StubHandler(HttpStatusCode.OK, jwks));
        var options = new Options { Jwt = jwt, JwksUrl = "https://issuer.example/jwks" };

        var exitCode = await RunAsync(options, httpClient);

        Assert.Equal(ExitCodes.Valid, exitCode);
        Assert.Contains("signature verified with kid 'k1'", _output.ToString());
    }

    [Fact]
    public async Task JwksUrlReturningAnError_IsAUsageError()
    {
        using var httpClient = new HttpClient(new StubHandler(HttpStatusCode.NotFound, "not found"));
        var options = new Options { Jwt = "a.b.c", JwksUrl = "https://issuer.example/jwks" };

        var exitCode = await RunAsync(options, httpClient);

        Assert.Equal(ExitCodes.UsageError, exitCode);
        Assert.Contains("404", _error.ToString());
    }

    [Fact]
    public async Task TokenSignedWithAnotherKey_IsInvalid()
    {
        using var other = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(other), SecurityAlgorithms.RsaSha256);
        var options = new Options { Jwt = jwt, JwksJson = TestTokens.Jwks(TestTokens.RsaJwk(_rsa, "k1")) };

        var exitCode = await RunAsync(options);

        Assert.Equal(ExitCodes.Invalid, exitCode);
        Assert.Contains("Result: token validation failed", _output.ToString());
    }

    [Fact]
    public async Task ExpiredToken_FailsOnlyWithValidateLifetime()
    {
        var jwt = TestTokens.CreateToken(
            new RsaSecurityKey(_rsa),
            SecurityAlgorithms.RsaSha256,
            expires: DateTime.UtcNow.AddHours(-1),
            notBefore: DateTime.UtcNow.AddHours(-2));
        var keyFile = WriteTempFile(_rsa.ExportSubjectPublicKeyInfoPem());

        var withoutLifetime = await RunAsync(new Options { Jwt = jwt, RsaKeyFile = keyFile });
        var withLifetime = await RunAsync(new Options { Jwt = jwt, RsaKeyFile = keyFile, ValidateLifetime = true });

        Assert.Equal(ExitCodes.Valid, withoutLifetime);
        Assert.Equal(ExitCodes.Invalid, withLifetime);
        Assert.Contains(nameof(SecurityTokenExpiredException), _output.ToString());
    }

    [Fact]
    public async Task Manual_WithClaimChecks_WarnsThatTheyAreIgnored()
    {
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256);
        var options = new Options
        {
            Jwt = jwt,
            RsaKeyFile = WriteTempFile(_rsa.ExportSubjectPublicKeyInfoPem()),
            Manual = true,
            Issuer = "ignored",
        };

        var exitCode = await RunAsync(options);

        Assert.Equal(ExitCodes.Valid, exitCode);
        Assert.Contains("--manual checks the signature only", _output.ToString());
    }

    [Fact]
    public async Task MissingKeyFile_IsAUsageError()
    {
        var options = new Options { Jwt = "a.b.c", RsaKeyFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pem") };

        var exitCode = await RunAsync(options);

        Assert.Equal(ExitCodes.UsageError, exitCode);
        Assert.StartsWith("Error:", _error.ToString());
    }

    [Fact]
    public async Task MalformedToken_IsInvalid()
    {
        var options = new Options { Jwt = "not-a-jwt", RsaKeyFile = WriteTempFile(_rsa.ExportSubjectPublicKeyInfoPem()) };

        var exitCode = await RunAsync(options);

        Assert.Equal(ExitCodes.Invalid, exitCode);
        Assert.Contains("Token format is not valid", _output.ToString());
    }

    private async Task<int> RunAsync(Options options, HttpClient? httpClient = null)
    {
        using var defaultClient = new HttpClient(new StubHandler(HttpStatusCode.InternalServerError, string.Empty));
        var command = new ValidateCommand(_output, _error, httpClient ?? defaultClient, TimeProvider.System);
        return await command.RunAsync(options, TestContext.Current.CancellationToken);
    }

    private string WriteTempFile(string contents)
    {
        var path = Path.GetTempFileName();
        _tempFiles.Add(path);
        File.WriteAllText(path, contents);
        return path;
    }

    private sealed class StubHandler(HttpStatusCode statusCode, string content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(statusCode) { Content = new StringContent(content) });
    }
}
