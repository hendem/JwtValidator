namespace JwtValidator.Tests;

public class OptionsTests
{
    [Fact]
    public void ValidOptions_HaveNoUsageError()
    {
        var options = new Options { Jwt = "a.b.c", JwksUrl = "https://issuer.example/jwks" };

        Assert.Null(options.GetUsageError());
    }

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
