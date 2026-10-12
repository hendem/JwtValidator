using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator.Tests;

public class TokenDiagnosticsTests
{
    [Theory]
    [InlineData(30, "30 seconds")]
    [InlineData(60, "1 minute")]
    [InlineData(2 * 3600, "2 hours")]
    [InlineData(-3 * 86400, "3 days")]
    [InlineData(800 * 86400, "2 years")]
    public void Humanize_UsesTheLargestWholeUnit(int seconds, string expected)
    {
        Assert.Equal(expected, TokenDiagnostics.Humanize(TimeSpan.FromSeconds(seconds)));
    }

    [Fact]
    public void WriteToken_ShowsClaimsAndExpiry()
    {
        using var rsa = TestTokens.NewRsa();
        var now = DateTime.UtcNow;
        var jwt = TestTokens.CreateToken(
            new RsaSecurityKey(rsa) { KeyId = "k1" },
            SecurityAlgorithms.RsaSha256,
            expires: now.AddHours(-3),
            notBefore: now.AddHours(-4));
        var output = new StringWriter();

        new TokenDiagnostics(output, now, verbose: false).WriteToken(new JsonWebToken(jwt), TestTokens.NoClaimChecks);

        var text = output.ToString();
        Assert.Contains("alg: RS256   kid: k1", text);
        Assert.Contains($"iss: {TestTokens.Issuer}", text);
        Assert.Contains($"aud: {TestTokens.Audience}", text);
        Assert.Contains("(expired 3 hours ago; not enforced without --validate-lifetime)", text);
        Assert.DoesNotContain("Payload:", text);
    }

    [Fact]
    public void WriteToken_Verbose_ShowsDecodedPayload()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        var output = new StringWriter();

        new TokenDiagnostics(output, DateTimeOffset.UtcNow, verbose: true).WriteToken(new JsonWebToken(jwt), TestTokens.NoClaimChecks);

        Assert.Contains("Payload:", output.ToString());
        Assert.Contains("\"sub\": \"test-user\"", output.ToString());
    }

    [Fact]
    public void WriteKeys_WarnsWhenTheTokenKidIsNotInTheKeySet()
    {
        using var rsa = TestTokens.NewRsa();
        var keySet = KeyLoader.FromJwks(TestTokens.Jwks(TestTokens.RsaJwk(rsa, "a"), TestTokens.RsaJwk(rsa, "b")), "jwks");
        var output = new StringWriter();

        new TokenDiagnostics(output, DateTimeOffset.UtcNow, verbose: false).WriteKeys(keySet, "missing");

        Assert.Contains("the token's kid 'missing' is not in the key set (available: a, b)", output.ToString());
    }

    [Fact]
    public void GetKid_ReturnsNullWhenTheHeaderHasNoKid()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

        Assert.Null(TokenDiagnostics.GetKid(new JsonWebToken(jwt)));
    }

    [Fact]
    public void TryRead_RejectsMalformedTokens()
    {
        Assert.False(TokenDiagnostics.TryRead("not-a-jwt", out _, out var error));
        Assert.NotNull(error);
    }
}
