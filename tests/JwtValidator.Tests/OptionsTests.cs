namespace JwtValidator.Tests;

/// <summary>Tests for <see cref="Options"/>.</summary>
public class OptionsTests
{
    /// <summary>One token source and one key source is a valid combination.</summary>
    [Fact]
    public void ValidOptions_HaveNoUsageError()
    {
        var options = new Options { Jwt = "a.b.c", JwksUrl = "https://issuer.example/jwks" };

        Assert.Null(options.GetUsageError());
    }

    /// <summary>Missing or conflicting sources, a non-HTTP URL and a negative clock skew are usage errors.</summary>
    /// <param name="jwt">The --jwt value.</param>
    /// <param name="jwtFile">The --jwt-file value.</param>
    /// <param name="jwksUrl">The --jwks-url value.</param>
    /// <param name="jwksFile">The --jwks-file value.</param>
    /// <param name="rsaKeyFile">The --rsa-key-file value.</param>
    /// <param name="clockSkew">The --clock-skew value.</param>
    /// <param name="expectedMessage">Text the usage error must contain.</param>
    [Theory]
    [InlineData(null, null, null, "jwks.json", null, 300, "--jwt or --jwt-file")]
    [InlineData("a.b.c", "token.jwt", null, "jwks.json", null, 300, "--jwt or --jwt-file")]
    [InlineData("a.b.c", null, null, null, null, 300, "--jwks-url")]
    [InlineData("a.b.c", null, null, "jwks.json", "key.pem", 300, "--jwks-url")]
    [InlineData("a.b.c", null, "/relative/jwks", null, null, 300, "absolute http or https URL")]
    [InlineData("a.b.c", null, "file:///c:/jwks.json", null, null, 300, "absolute http or https URL")]
    [InlineData("a.b.c", null, null, "jwks.json", null, -1, "--clock-skew")]
    public void InvalidOptions_ReportAUsageError(
        string? jwt, string? jwtFile, string? jwksUrl, string? jwksFile, string? rsaKeyFile, int clockSkew, string expectedMessage)
    {
        var options = new Options
        {
            Jwt = jwt,
            JwtFile = jwtFile,
            JwksUrl = jwksUrl,
            JwksFile = jwksFile,
            RsaKeyFile = rsaKeyFile,
            ClockSkewSeconds = clockSkew,
        };

        Assert.Contains(expectedMessage, options.GetUsageError());
    }
}
