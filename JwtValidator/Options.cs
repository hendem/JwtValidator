using CommandLine;

namespace JwtValidator;

internal sealed class Options
{
    [Option('j', "jwt", HelpText = "The JWT to validate.")]
    public string? Jwt { get; set; }

    [Option("jwt-file", HelpText = "The file path of the JWT.")]
    public string? JwtFile { get; set; }

    [Option('u', "jwks-url", HelpText = "The URL of the JWKS.")]
    public string? JwksUrl { get; set; }

    [Option("jwks-json", HelpText = "The JWKS payload.")]
    public string? JwksJson { get; set; }

    [Option("jwks-file", HelpText = "The file path of a JWKS file.")]
    public string? JwksFile { get; set; }

    [Option("rsa-key-file", HelpText = "The file path of the RSA key in PEM format.")]
    public string? RsaKeyFile { get; set; }

    [Option("manual", HelpText = "Verify the RSA signature directly instead of using the token handler. Checks the signature only.")]
    public bool Manual { get; set; }

    [Option("issuer", HelpText = "Require the token's 'iss' claim to equal this value.")]
    public string? Issuer { get; set; }

    [Option("audience", HelpText = "Require the token's 'aud' claim to contain this value.")]
    public string? Audience { get; set; }

    [Option("validate-lifetime", HelpText = "Reject tokens that are expired or not yet valid (exp/nbf).")]
    public bool ValidateLifetime { get; set; }

    [Option("clock-skew", Default = 300, HelpText = "Allowed clock skew in seconds when validating the lifetime.")]
    public int ClockSkewSeconds { get; set; }

    [Option('v', "verbose", Default = false, HelpText = "Set output to verbose messages.")]
    public bool Verbose { get; set; }

    public bool HasClaimChecks => Issuer is not null || Audience is not null || ValidateLifetime;

    /// <summary>Returns a message describing the first invalid option combination, or null if the options are usable.</summary>
    public string? GetUsageError()
    {
        if (IsSet(Jwt) == IsSet(JwtFile))
        {
            return "Provide exactly one of --jwt or --jwt-file.";
        }

        var keySourceCount = new[] { JwksUrl, JwksJson, JwksFile, RsaKeyFile }.Count(IsSet);
        if (keySourceCount != 1)
        {
            return "Provide exactly one of --jwks-url, --jwks-json, --jwks-file or --rsa-key-file.";
        }

        if (IsSet(JwksUrl) && !(Uri.TryCreate(JwksUrl, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https"))
        {
            return $"--jwks-url must be an absolute http or https URL: '{JwksUrl}'.";
        }

        if (ClockSkewSeconds < 0)
        {
            return "--clock-skew must not be negative.";
        }

        return null;
    }

    public ValidationSettings ToValidationSettings() =>
        new(Issuer, Audience, ValidateLifetime, TimeSpan.FromSeconds(ClockSkewSeconds));

    private static bool IsSet(string? value) => !string.IsNullOrWhiteSpace(value);
}
