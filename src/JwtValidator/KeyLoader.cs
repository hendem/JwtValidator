using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator;

/// <summary>Describes one entry of a key set as it appeared in the source, whether or not it could be used.</summary>
internal sealed record KeyDescription(string? Kid, string? Kty, string? Alg, string? Use);

/// <summary>The signing keys loaded from one source, plus a description of every entry the source contained.</summary>
internal sealed record KeySet(string Source, IReadOnlyList<SecurityKey> Keys, IReadOnlyList<KeyDescription> Entries);

/// <summary>Loads signing keys from a PEM file or a JWKS (inline JSON, file or URL).</summary>
internal static class KeyLoader
{
    /// <summary>Loads the keys from whichever key source is set in the options.</summary>
    /// <param name="options">The options; exactly one key source is expected to be set.</param>
    /// <param name="httpClient">The client used to fetch the JWKS when <see cref="Options.JwksUrl"/> is set.</param>
    /// <param name="cancellationToken">A token to cancel file reads and the HTTP request.</param>
    /// <returns>The loaded key set.</returns>
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

    /// <summary>Creates a key set containing the RSA public key from a PEM document.</summary>
    /// <param name="pem">A PEM-encoded RSA public or private key. Only the public part is kept.</param>
    /// <param name="source">A description of where the key came from, used in the output.</param>
    /// <returns>A key set with a single RSA key.</returns>
    /// <exception cref="ArgumentException">The text doesn't contain a supported PEM-encoded RSA key.</exception>
    public static KeySet FromRsaPem(string pem, string source)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);

        // Keep only the public parameters so the key doesn't depend on the lifetime of the RSA instance.
        var key = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: false));
        return new KeySet(source, [key], [new KeyDescription(Kid: null, Kty: "RSA", Alg: null, Use: null)]);
    }

    /// <summary>Creates a key set from a JWKS document.</summary>
    /// <param name="json">The JWKS JSON, an object with a <c>keys</c> array.</param>
    /// <param name="source">A description of where the JWKS came from, used in the output.</param>
    /// <returns>The usable signing keys plus a description of every entry in the JWKS.</returns>
    /// <exception cref="JsonException">The text isn't valid JSON.</exception>
    /// <exception cref="InvalidDataException">The JSON has no <c>keys</c> array.</exception>
    public static KeySet FromJwks(string json, string source)
    {
        var entries = DescribeJwksEntries(json);
        var keys = new JsonWebKeySet(json).GetSigningKeys().ToList();
        return new KeySet(source, keys, entries);
    }

    /// <summary>Gets the RSA public parameters of a key.</summary>
    /// <param name="key">An RSA, X.509 or JSON web key.</param>
    /// <returns>The public modulus and exponent, or null if the key isn't an RSA key.</returns>
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

    /// <summary>Reads the kid, kty, alg and use of every entry in a JWKS.</summary>
    /// <remarks>JsonWebKeySet silently drops entries it can't use, so the raw entries are read to be able to report them.</remarks>
    /// <param name="json">The JWKS JSON.</param>
    /// <returns>One description per entry in the <c>keys</c> array.</returns>
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

    /// <summary>Gets a string property from a JSON object.</summary>
    /// <param name="element">The JSON element to read from.</param>
    /// <param name="propertyName">The name of the property.</param>
    /// <returns>The property value, or null if the element isn't an object or the property is missing or not a string.</returns>
    private static string? GetString(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(propertyName, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
