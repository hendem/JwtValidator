using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator;

internal sealed record ValidationSettings(string? Issuer, string? Audience, bool ValidateLifetime, TimeSpan ClockSkew);

internal sealed record ValidationOutcome(bool IsValid, string? Error = null, Exception? Exception = null, SecurityKey? SigningKey = null)
{
    public static ValidationOutcome Valid(SecurityKey? signingKey) => new(true, SigningKey: signingKey);

    public static ValidationOutcome Invalid(string error, Exception? exception = null) => new(false, error, exception);
}

internal static class TokenValidator
{
    public static readonly string[] SupportedAlgorithms =
    [
        SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha512,
    ];

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

    // IdentityModel messages are long and multi-line; keep the summary to one line. Verbose output shows the full message.
    private static string Describe(Exception? exception) => exception switch
    {
        null => "Unknown validation error.",
        SecurityTokenSignatureKeyNotFoundException =>
            "None of the keys could verify the signature; the token was probably signed with a different key.",
        SecurityTokenInvalidSignatureException => "The signature is invalid.",
        _ => $"{exception.GetType().Name}: {exception.Message.Split('\n')[0].TrimEnd()}",
    };
}
