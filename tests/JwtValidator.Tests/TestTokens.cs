using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator.Tests;

/// <summary>Creates keys, JWKS documents and signed tokens for tests.</summary>
internal static class TestTokens
{
    public const string Issuer = "https://issuer.example";
    public const string Audience = "test-audience";

    public static readonly ValidationSettings NoClaimChecks = new(null, null, false, TimeSpan.FromMinutes(5));

    /// <summary>Creates a new 2048-bit RSA key pair.</summary>
    /// <returns>The key pair; the caller disposes it.</returns>
    public static RSA NewRsa() => RSA.Create(2048);

    /// <summary>Creates a new EC key pair on the given curve.</summary>
    /// <param name="curve">The named curve, such as P-256.</param>
    /// <returns>The key pair; the caller disposes it.</returns>
    public static ECDsa NewEcdsa(ECCurve curve) => ECDsa.Create(curve);

    /// <summary>Creates a signed token with a <c>sub</c> claim and the given issuer, audience and lifetime.</summary>
    /// <param name="signingKey">The private key to sign with. Its KeyId, if set, becomes the token's kid.</param>
    /// <param name="algorithm">The signing algorithm, such as RS256.</param>
    /// <param name="expires">The exp claim; defaults to one hour from now.</param>
    /// <param name="notBefore">The nbf and iat claims; default to one minute ago.</param>
    /// <param name="issuer">The iss claim.</param>
    /// <param name="audience">The aud claim.</param>
    /// <returns>The token in compact serialization format.</returns>
    public static string CreateToken(
        SecurityKey signingKey,
        string algorithm,
        DateTime? expires = null,
        DateTime? notBefore = null,
        string issuer = Issuer,
        string audience = Audience)
    {
        var now = DateTime.UtcNow;
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity([new Claim("sub", "test-user")]),
            IssuedAt = notBefore ?? now.AddMinutes(-1),
            NotBefore = notBefore ?? now.AddMinutes(-1),
            Expires = expires ?? now.AddHours(1),
            SigningCredentials = new SigningCredentials(signingKey, algorithm),
        });
    }

    /// <summary>Creates a JWK for the public part of an RSA key.</summary>
    /// <param name="rsa">The RSA key.</param>
    /// <param name="kid">The kid, or null to leave it out.</param>
    /// <returns>The JWK as JSON.</returns>
    public static string RsaJwk(RSA rsa, string? kid)
    {
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        return Serialize(new Dictionary<string, string?>
        {
            ["kty"] = "RSA",
            ["kid"] = kid,
            ["use"] = "sig",
            ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
            ["e"] = Base64UrlEncoder.Encode(parameters.Exponent),
        });
    }

    /// <summary>Creates a JWK for the public part of an EC key.</summary>
    /// <param name="ecdsa">The EC key.</param>
    /// <param name="crv">The JWK curve name, such as P-256.</param>
    /// <param name="kid">The kid, or null to leave it out.</param>
    /// <returns>The JWK as JSON.</returns>
    public static string EcJwk(ECDsa ecdsa, string crv, string? kid)
    {
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        return Serialize(new Dictionary<string, string?>
        {
            ["kty"] = "EC",
            ["kid"] = kid,
            ["use"] = "sig",
            ["crv"] = crv,
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y),
        });
    }

    /// <summary>Wraps JWKs in a JWKS document.</summary>
    /// <param name="jwks">The JWKs as JSON.</param>
    /// <returns>A JWKS with the JWKs in its <c>keys</c> array.</returns>
    public static string Jwks(params string[] jwks) => $$"""{"keys":[{{string.Join(",", jwks)}}]}""";

    /// <summary>Serializes a JWK, leaving out members with a null value.</summary>
    /// <param name="jwk">The JWK members.</param>
    /// <returns>The JWK as JSON.</returns>
    private static string Serialize(Dictionary<string, string?> jwk) =>
        JsonSerializer.Serialize(jwk.Where(p => p.Value is not null).ToDictionary());
}
