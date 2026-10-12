using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator;

/// <summary>Describes one entry of a key set as it appeared in the source, whether or not it could be used.</summary>
internal sealed record KeyDescription(string? Kid, string? Kty, string? Alg, string? Use);

/// <summary>The signing keys loaded from one source, plus a description of every entry the source contained.</summary>
internal sealed record KeySet(string Source, IReadOnlyList<SecurityKey> Keys, IReadOnlyList<KeyDescription> Entries);

internal static class KeyLoader
{
    public static async Task<KeySet> LoadAsync(Options options, HttpClient httpClient, CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrWhiteSpace(options.RsaKeyFile))
        {
            var pem = await File.ReadAllTextAsync(options.RsaKeyFile, cancellationToken);
            return FromRsaPem(pem, $"RSA key file '{options.RsaKeyFile}'");
        }

        if (!string.IsNullOrWhiteSpace(options.JwksJson))
        {
            return FromJwks(options.JwksJson, "JWKS from --jwks-json");
        }

        if (!string.IsNullOrWhiteSpace(options.JwksFile))
        {
            var json = await File.ReadAllTextAsync(options.JwksFile, cancellationToken);
            return FromJwks(json, $"JWKS file '{options.JwksFile}'");
        }

        var jwks = await httpClient.GetStringAsync(options.JwksUrl, cancellationToken);
        return FromJwks(jwks, $"JWKS from {options.JwksUrl}");
    }

    public static KeySet FromRsaPem(string pem, string source)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);

        // Keep only the public parameters so the key doesn't depend on the lifetime of the RSA instance.
        var key = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: false));
        return new KeySet(source, [key], [new KeyDescription(Kid: null, Kty: "RSA", Alg: null, Use: null)]);
    }

    public static KeySet FromJwks(string json, string source)
    {
        var entries = DescribeJwksEntries(json);
        var keys = new JsonWebKeySet(json).GetSigningKeys().ToList();
        return new KeySet(source, keys, entries);
    }

    /// <summary>Gets the RSA public parameters of a key, or null if it isn't an RSA key.</summary>
    public static RSAParameters? GetRsaParameters(SecurityKey key) => key switch
    {
        RsaSecurityKey { Rsa: { } rsa } => rsa.ExportParameters(includePrivateParameters: false),
        RsaSecurityKey rsaKey => rsaKey.Parameters,
        X509SecurityKey { PublicKey: RSA rsa } => rsa.ExportParameters(includePrivateParameters: false),
        JsonWebKey { Kty: JsonWebAlgorithmsKeyTypes.RSA } jwk => new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(jwk.N),
            Exponent = Base64UrlEncoder.DecodeBytes(jwk.E),
        },
        _ => null,
    };

    // JsonWebKeySet silently drops entries it can't use, so read the raw entries to be able to report them.
    private static List<KeyDescription> DescribeJwksEntries(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("The JWKS must be a JSON object with a 'keys' array.");
        }

        return keys.EnumerateArray()
            .Select(k => new KeyDescription(GetString(k, "kid"), GetString(k, "kty"), GetString(k, "alg"), GetString(k, "use")))
            .ToList();
    }

    private static string? GetString(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(propertyName, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
