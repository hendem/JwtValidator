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

    public static RSA NewRsa() => RSA.Create(2048);

    public static ECDsa NewEcdsa(ECCurve curve) => ECDsa.Create(curve);

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

    public static string Jwks(params string[] jwks) => $$"""{"keys":[{{string.Join(",", jwks)}}]}""";

    private static string Serialize(Dictionary<string, string?> jwk) =>
        JsonSerializer.Serialize(jwk.Where(p => p.Value is not null).ToDictionary());
}
