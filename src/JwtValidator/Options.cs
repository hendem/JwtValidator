using CommandLine;

namespace JwtValidator;

/// <summary>Command-line options for the tool.</summary>
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

    /// <summary>Gets whether any issuer, audience or lifetime check was requested.</summary>
    public bool HasClaimChecks => Issuer is not null || Audience is not null || ValidateLifetime;

    /// <summary>Checks that exactly one token source and one key source are set and that the values are usable.</summary>
    /// <returns>A message describing the first invalid option combination, or null if the options are usable.</returns>
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

    /// <summary>Creates the validation settings that correspond to the claim check options.</summary>
    /// <returns>The issuer, audience, lifetime and clock skew settings to validate with.</returns>
    public ValidationSettings ToValidationSettings() =>
        new(Issuer, Audience, ValidateLifetime, TimeSpan.FromSeconds(ClockSkewSeconds));

    /// <summary>Determines whether an option value was supplied.</summary>
    /// <param name="value">The option value.</param>
    /// <returns>True if the value is not null, empty or whitespace.</returns>
    private static bool IsSet(string? value) => !string.IsNullOrWhiteSpace(value);
}
