using System.Net;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator.Tests;

/// <summary>End-to-end tests for <see cref="ValidateCommand"/>, covering output and exit codes.</summary>
public sealed class ValidateCommandTests : IDisposable
{
    private readonly RSA _rsa = TestTokens.NewRsa();
    private readonly List<string> _tempFiles = [];
    private readonly StringWriter _output = new();
    private readonly StringWriter _error = new();

    /// <summary>Disposes the test key and deletes the temporary files.</summary>
    public void Dispose()
    {
        _rsa.Dispose();
        foreach (var file in _tempFiles)
        {
            File.Delete(file);
        }
    }

    /// <summary>A token file ending in a newline is read and validates.</summary>
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

    /// <summary>A token validates against a JWKS fetched over HTTP and the result names the signing kid.</summary>
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

    /// <summary>An HTTP error from the JWKS URL is a usage error that reports the status code.</summary>
    [Fact]
    public async Task JwksUrlReturningAnError_IsAUsageError()
    {
        using var httpClient = new HttpClient(new StubHandler(HttpStatusCode.NotFound, "not found"));
        var options = new Options { Jwt = "a.b.c", JwksUrl = "https://issuer.example/jwks" };

        var exitCode = await RunAsync(options, httpClient);

        Assert.Equal(ExitCodes.UsageError, exitCode);
        Assert.Contains("404", _error.ToString());
    }

    /// <summary>A token signed with a key that isn't in the JWKS exits with the invalid code.</summary>
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

    /// <summary>An expired token exits as valid by default and as invalid with --validate-lifetime.</summary>
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

    /// <summary>Using --manual together with claim checks warns that the claim checks are ignored.</summary>
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

    /// <summary>A key file that doesn't exist is a usage error.</summary>
    [Fact]
    public async Task MissingKeyFile_IsAUsageError()
    {
        var options = new Options { Jwt = "a.b.c", RsaKeyFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pem") };

        var exitCode = await RunAsync(options);

        Assert.Equal(ExitCodes.UsageError, exitCode);
        Assert.StartsWith("Error:", _error.ToString());
    }

    /// <summary>A JWKS that isn't an object with a <c>keys</c> array is a usage error, not an unhandled exception.</summary>
    /// <param name="jwks">The --jwks-json value.</param>
    [Theory]
    [InlineData("""{"foo":1}""")]
    [InlineData("""{"keys":"not-an-array"}""")]
    [InlineData("[]")]
    [InlineData("\"just a string\"")]
    [InlineData("not json")]
    public async Task MalformedJwks_IsAUsageError(string jwks)
    {
        var options = new Options { Jwt = "a.b.c", JwksJson = jwks };

        var exitCode = await RunAsync(options);

        Assert.Equal(ExitCodes.UsageError, exitCode);
        Assert.StartsWith("Error:", _error.ToString());
    }

    /// <summary>A PEM file whose key data is corrupt is a usage error, not an unhandled exception.</summary>
    [Fact]
    public async Task CorruptPemKey_IsAUsageError()
    {
        var corruptPem = "-----BEGIN PUBLIC KEY-----\nAAAAAAAAAAAAAAAA\n-----END PUBLIC KEY-----\n";
        var options = new Options { Jwt = "a.b.c", RsaKeyFile = WriteTempFile(corruptPem) };

        var exitCode = await RunAsync(options);

        Assert.Equal(ExitCodes.UsageError, exitCode);
        Assert.StartsWith("Error:", _error.ToString());
    }

    /// <summary>A malformed token exits with the invalid code and says the format isn't valid.</summary>
    [Fact]
    public async Task MalformedToken_IsInvalid()
    {
        var options = new Options { Jwt = "not-a-jwt", RsaKeyFile = WriteTempFile(_rsa.ExportSubjectPublicKeyInfoPem()) };

        var exitCode = await RunAsync(options);

        Assert.Equal(ExitCodes.Invalid, exitCode);
        Assert.Contains("Token format is not valid", _output.ToString());
    }

    /// <summary>Runs the command with the test's output writers.</summary>
    /// <param name="options">The options to run with.</param>
    /// <param name="httpClient">The HTTP client to use; by default, one that returns HTTP 500.</param>
    /// <returns>The exit code.</returns>
    private async Task<int> RunAsync(Options options, HttpClient? httpClient = null)
    {
        using var defaultClient = new HttpClient(new StubHandler(HttpStatusCode.InternalServerError, string.Empty));
        var command = new ValidateCommand(_output, _error, httpClient ?? defaultClient, TimeProvider.System);
        return await command.RunAsync(options, TestContext.Current.CancellationToken);
    }

    /// <summary>Writes text to a temporary file that is deleted when the test finishes.</summary>
    /// <param name="contents">The file contents.</param>
    /// <returns>The path of the file.</returns>
    private string WriteTempFile(string contents)
    {
        var path = Path.GetTempFileName();
        _tempFiles.Add(path);
        File.WriteAllText(path, contents);
        return path;
    }

    /// <summary>An HTTP handler that returns the same response to every request.</summary>
    /// <param name="statusCode">The response status code.</param>
    /// <param name="content">The response body.</param>
    private sealed class StubHandler(HttpStatusCode statusCode, string content) : HttpMessageHandler
    {
        /// <summary>Returns the configured response without sending the request.</summary>
        /// <param name="request">The request, which is ignored.</param>
        /// <param name="cancellationToken">Not used.</param>
        /// <returns>The configured response.</returns>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(statusCode) { Content = new StringContent(content) });
    }
}
