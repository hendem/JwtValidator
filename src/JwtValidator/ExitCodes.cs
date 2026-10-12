namespace JwtValidator;

/// <summary>Process exit codes returned by the tool.</summary>
internal static class ExitCodes
{
    /// <summary>The token is valid.</summary>
    public const int Valid = 0;

    /// <summary>The token is malformed, its signature is invalid, or a claim check failed.</summary>
    public const int Invalid = 1;

    /// <summary>The options were missing or conflicting, or an input could not be read.</summary>
    public const int UsageError = 2;
}
