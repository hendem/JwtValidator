using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator;

/// <summary>The optional claim checks to apply in addition to the signature check.</summary>
/// <param name="Issuer">The required issuer, or null to skip the issuer check.</param>
/// <param name="Audience">The required audience, or null to skip the audience check.</param>
/// <param name="ValidateLifetime">Whether to reject expired and not-yet-valid tokens.</param>
/// <param name="ClockSkew">The clock skew allowed when validating the lifetime.</param>
internal sealed record ValidationSettings(string? Issuer, string? Audience, bool ValidateLifetime, TimeSpan ClockSkew);

/// <summary>The result of validating a token.</summary>
/// <param name="IsValid">Whether the token passed validation.</param>
/// <param name="Error">A one-line description of why validation failed, or null if it passed.</param>
/// <param name="Exception">The exception that caused the failure, if any.</param>
/// <param name="SigningKey">The key that verified the signature, if validation passed.</param>
internal sealed record ValidationOutcome(bool IsValid, string? Error = null, Exception? Exception = null, SecurityKey? SigningKey = null)
{
    /// <summary>Creates a successful outcome.</summary>
    /// <param name="signingKey">The key that verified the signature, if known.</param>
    /// <returns>A valid outcome.</returns>
    public static ValidationOutcome Valid(SecurityKey? signingKey) => new(true, SigningKey: signingKey);

    /// <summary>Creates a failed outcome.</summary>
    /// <param name="error">A one-line description of the failure.</param>
    /// <param name="exception">The exception that caused the failure, if any.</param>
    /// <returns>An invalid outcome.</returns>
    public static ValidationOutcome Invalid(string error, Exception? exception = null) => new(false, error, exception);
}

/// <summary>Validates JWT signatures and, optionally, the issuer, audience and lifetime.</summary>
internal static class TokenValidator
{
    /// <summary>The signing algorithms a token may use.</summary>
    public static readonly string[] SupportedAlgorithms =
    [
        SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha512,
    ];

    /// <summary>Builds the token handler's validation parameters.</summary>
    /// <param name="keys">The keys the signature may be verified with.</param>
    /// <param name="settings">The claim checks to enable.</param>
    /// <returns>Parameters that require a signed token and enable only the requested claim checks.</returns>
    public static TokenValidationParameters CreateParameters(IEnumerable<SecurityKey> keys, ValidationSettings settings) => new()
    {
        IssuerSigningKeys = keys,
        ValidateIssuerSigningKey = true,
        RequireSignedTokens = true,
        ValidAlgorithms = SupportedAlgorithms,
        ValidateIssuer = settings.Issuer is not null,
        ValidIssuer = settings.Issuer,
        ValidateAudience = settings.Audience is not null,
        ValidAudience = settings.Audience,
        ValidateLifetime = settings.ValidateLifetime,
        RequireExpirationTime = settings.ValidateLifetime,
        ClockSkew = settings.ClockSkew,
    };

    /// <summary>Validates a token with <see cref="JsonWebTokenHandler"/>.</summary>
    /// <param name="jwt">The token in compact serialization format.</param>
    /// <param name="keys">The keys the signature may be verified with.</param>
    /// <param name="settings">The claim checks to apply.</param>
    /// <returns>The validation outcome, including the signing key when the token is valid.</returns>
    public static async Task<ValidationOutcome> ValidateAsync(string jwt, IEnumerable<SecurityKey> keys, ValidationSettings settings)
    {
        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(jwt, CreateParameters(keys, settings));

        return result.IsValid
            ? ValidationOutcome.Valid((result.SecurityToken as JsonWebToken)?.SigningKey)
            : ValidationOutcome.Invalid(Describe(result.Exception), result.Exception);
    }

    /// <summary>
    /// Verifies an RSA PKCS#1 signature (RS256/RS384/RS512) directly with System.Security.Cryptography,
    /// independently of the token handler. Claims are not checked.
    /// </summary>
    /// <param name="token">The parsed token.</param>
    /// <param name="keys">The keys to try. Keys whose kid matches the token are tried first; non-RSA keys are skipped.</param>
    /// <returns>The validation outcome, including the signing key when the signature is valid.</returns>
    public static ValidationOutcome ValidateSignatureManually(JsonWebToken token, IEnumerable<SecurityKey> keys)
    {
        HashAlgorithmName? hashAlgorithm = token.Alg switch
        {
            SecurityAlgorithms.RsaSha256 => HashAlgorithmName.SHA256,
            SecurityAlgorithms.RsaSha384 => HashAlgorithmName.SHA384,
            SecurityAlgorithms.RsaSha512 => HashAlgorithmName.SHA512,
            _ => null,
        };
        if (hashAlgorithm is null)
        {
            return ValidationOutcome.Invalid($"Manual validation supports RS256, RS384 and RS512 only; the token uses '{token.Alg}'.");
        }

        byte[] signature;
        try
        {
            signature = Base64UrlEncoder.DecodeBytes(token.EncodedSignature);
        }
        catch (FormatException ex)
        {
            return ValidationOutcome.Invalid("The signature is not valid base64url.", ex);
        }

        var signedData = Encoding.ASCII.GetBytes($"{token.EncodedHeader}.{token.EncodedPayload}");

        // Try keys with a matching kid first, then the rest, mirroring the token handler's behaviour.
        var candidates = keys.OrderByDescending(k => k.KeyId is not null && k.KeyId == token.Kid);
        foreach (var key in candidates)
        {
            if (KeyLoader.GetRsaParameters(key) is not { } parameters)
            {
                continue;
            }

            using var rsa = RSA.Create(parameters);
            if (rsa.VerifyData(signedData, signature, hashAlgorithm.Value, RSASignaturePadding.Pkcs1))
            {
                return ValidationOutcome.Valid(key);
            }
        }

        return ValidationOutcome.Invalid("The signature does not match any of the provided RSA keys.");
    }

    /// <summary>Turns a validation exception into a one-line description.</summary>
    /// <remarks>IdentityModel messages are long and multi-line, so only a summary is returned. Verbose output shows the full message.</remarks>
    /// <param name="exception">The exception reported by the token handler.</param>
    /// <returns>A one-line description of the failure.</returns>
    private static string Describe(Exception? exception) => exception switch
    {
        null => "Unknown validation error.",
        SecurityTokenSignatureKeyNotFoundException =>
            "None of the keys could verify the signature; the token was probably signed with a different key.",
        SecurityTokenInvalidSignatureException => "The signature is invalid.",
        _ => $"{exception.GetType().Name}: {exception.Message.Split('\n')[0].TrimEnd()}",
    };
}
