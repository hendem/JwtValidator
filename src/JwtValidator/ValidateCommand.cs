using System.Text.Json;

namespace JwtValidator;

/// <summary>Runs one validation for the given options and returns the process exit code.</summary>
internal sealed class ValidateCommand(TextWriter output, TextWriter error, HttpClient httpClient, TimeProvider timeProvider)
{
    public async Task<int> RunAsync(Options options, CancellationToken cancellationToken = default)
    {
        string jwt;
        KeySet keySet;
        try
        {
            jwt = await ReadJwtAsync(options, cancellationToken);
            keySet = await KeyLoader.LoadAsync(options, httpClient, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or HttpRequestException
                                       or TaskCanceledException or ArgumentException or JsonException)
        {
            error.WriteLine($"Error: {ex.Message}");
            return ExitCodes.UsageError;
        }

        if (!TokenDiagnostics.TryRead(jwt, out var token, out var readError) || token is null)
        {
            output.WriteLine($"Token format is not valid: {readError}");
            return ExitCodes.Invalid;
        }

        var settings = options.ToValidationSettings();
        var diagnostics = new TokenDiagnostics(output, timeProvider.GetUtcNow(), options.Verbose);
        diagnostics.WriteToken(token, settings);
        diagnostics.WriteKeys(keySet, TokenDiagnostics.GetKid(token));

        ValidationOutcome outcome;
        if (options.Manual)
        {
            if (options.HasClaimChecks)
            {
                output.WriteLine("Note: --manual checks the signature only; --issuer, --audience and --validate-lifetime are ignored.");
            }

            outcome = TokenValidator.ValidateSignatureManually(token, keySet.Keys);
        }
        else
        {
            outcome = await TokenValidator.ValidateAsync(jwt, keySet.Keys, settings);
        }

        if (outcome.IsValid)
        {
            var signedBy = outcome.SigningKey?.KeyId is { } kid ? $" (signature verified with kid '{kid}')" : string.Empty;
            output.WriteLine($"Result: token is valid{signedBy}.");
            return ExitCodes.Valid;
        }

        output.WriteLine($"Result: token validation failed. {outcome.Error}");
        if (options.Verbose && outcome.Exception is not null)
        {
            output.WriteLine($"Details: {outcome.Exception.Message}");
        }

        return ExitCodes.Invalid;
    }

    private async Task<string> ReadJwtAsync(Options options, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(options.JwtFile))
        {
            return options.Jwt!.Trim();
        }

        if (options.Verbose)
        {
            output.WriteLine($"Reading JWT from file: {options.JwtFile}");
        }

        // Files usually end with a newline, which would otherwise make the token unreadable.
        return (await File.ReadAllTextAsync(options.JwtFile, cancellationToken)).Trim();
    }
}
