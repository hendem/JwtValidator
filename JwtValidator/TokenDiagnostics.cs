using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator;

/// <summary>Writes human-readable details about a token and key set to help explain why validation passes or fails.</summary>
internal sealed class TokenDiagnostics(TextWriter output, DateTimeOffset now, bool verbose)
{
    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    public static bool TryRead(string jwt, out JsonWebToken? token, out string? error)
    {
        try
        {
            token = new JsonWebToken(jwt);
            error = null;
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or SecurityTokenException)
        {
            token = null;
            error = ex.Message;
            return false;
        }
    }

    /// <summary>Gets the token's kid, or null if it has none (JsonWebToken returns an empty string in that case).</summary>
    public static string? GetKid(JsonWebToken token) => string.IsNullOrEmpty(token.Kid) ? null : token.Kid;

    public void WriteToken(JsonWebToken token, ValidationSettings settings)
    {
        output.WriteLine("Token");
        output.WriteLine($"  alg: {token.Alg}   kid: {GetKid(token) ?? "(none)"}   typ: {(string.IsNullOrEmpty(token.Typ) ? "(none)" : token.Typ)}");
        WriteClaim("iss", token.Issuer);
        WriteClaim("sub", token.Subject);
        WriteClaim("aud", string.Join(", ", token.Audiences));

        if (TryGetTime(token, JwtRegisteredClaimNames.Iat) is { } issuedAt)
        {
            var status = issuedAt > now ? $"in the future by {Humanize(issuedAt - now)}" : $"{Humanize(now - issuedAt)} ago";
            WriteClaim("iat", $"{Format(issuedAt)} ({status})");
        }

        if (TryGetTime(token, JwtRegisteredClaimNames.Nbf) is { } notBefore)
        {
            var status = notBefore > now ? $"not valid for another {Humanize(notBefore - now)}" : "already valid";
            WriteClaim("nbf", $"{Format(notBefore)} ({status}{LifetimeNote(settings, notBefore > now)})");
        }

        if (TryGetTime(token, JwtRegisteredClaimNames.Exp) is { } expires)
        {
            var status = expires <= now ? $"expired {Humanize(now - expires)} ago" : $"expires in {Humanize(expires - now)}";
            WriteClaim("exp", $"{Format(expires)} ({status}{LifetimeNote(settings, expires <= now)})");
        }
        else
        {
            WriteClaim("exp", "(none)");
        }

        if (verbose)
        {
            output.WriteLine("  Header:");
            WriteIndentedJson(token.EncodedHeader);
            output.WriteLine("  Payload:");
            WriteIndentedJson(token.EncodedPayload);
        }
    }

    public void WriteKeys(KeySet keySet, string? tokenKid)
    {
        output.WriteLine($"Keys ({keySet.Source})");
        foreach (var entry in keySet.Entries)
        {
            output.WriteLine($"  kid: {entry.Kid ?? "(none)"}   kty: {entry.Kty ?? "?"}   alg: {entry.Alg ?? "-"}   use: {entry.Use ?? "-"}");
        }

        if (keySet.Keys.Count < keySet.Entries.Count)
        {
            output.WriteLine($"  Warning: only {keySet.Keys.Count} of {keySet.Entries.Count} keys could be used for signature validation; the rest were malformed or not signing keys.");
        }

        if (tokenKid is null)
        {
            output.WriteLine("  The token has no kid; every key will be tried.");
            return;
        }

        var kids = keySet.Keys.Select(k => k.KeyId).Where(kid => kid is not null).ToList();
        if (kids.Count > 0 && !kids.Contains(tokenKid))
        {
            output.WriteLine($"  Warning: the token's kid '{tokenKid}' is not in the key set (available: {string.Join(", ", kids)}); every key will be tried.");
        }
    }

    internal static string Humanize(TimeSpan span)
    {
        span = span.Duration();
        return span.TotalDays >= 365 ? Plural((int)(span.TotalDays / 365), "year")
            : span.TotalDays >= 1 ? Plural((int)span.TotalDays, "day")
            : span.TotalHours >= 1 ? Plural((int)span.TotalHours, "hour")
            : span.TotalMinutes >= 1 ? Plural((int)span.TotalMinutes, "minute")
            : Plural((int)span.TotalSeconds, "second");

        static string Plural(int count, string unit) => count == 1 ? $"1 {unit}" : $"{count} {unit}s";
    }

    private static string LifetimeNote(ValidationSettings settings, bool outsideLifetime) =>
        outsideLifetime && !settings.ValidateLifetime ? "; not enforced without --validate-lifetime" : string.Empty;

    private static DateTimeOffset? TryGetTime(JsonWebToken token, string claim)
    {
        if (token.TryGetPayloadValue<long>(claim, out var seconds))
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }

        return token.TryGetPayloadValue<double>(claim, out var fractional)
            ? DateTimeOffset.FromUnixTimeMilliseconds((long)(fractional * 1000))
            : null;
    }

    private static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    private void WriteClaim(string name, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            output.WriteLine($"  {name}: {value}");
        }
    }

    private void WriteIndentedJson(string encoded)
    {
        var json = Base64UrlEncoder.Decode(encoded);
        var formatted = JsonNode.Parse(json)?.ToJsonString(IndentedJson) ?? json;
        foreach (var line in formatted.Split('\n'))
        {
            output.WriteLine($"    {line.TrimEnd('\r')}");
        }
    }
}
