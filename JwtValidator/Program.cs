using CommandLine;
using CommandLine.Text;
using Microsoft.IdentityModel.Logging;

namespace JwtValidator;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        // This is a local troubleshooting tool, so show the claim values and key ids in validation errors.
        IdentityModelEventSource.ShowPII = true;

        using var parser = new Parser(settings => settings.HelpWriter = null);
        var parserResult = parser.ParseArguments<Options>(args);

        if (parserResult is NotParsed<Options> notParsed)
        {
            if (notParsed.Errors.IsVersion())
            {
                Console.WriteLine(HeadingInfo.Default);
                return ExitCodes.Valid;
            }

            DisplayHelp(parserResult);
            return notParsed.Errors.IsHelp() ? ExitCodes.Valid : ExitCodes.UsageError;
        }

        var options = parserResult.Value;
        if (options.GetUsageError() is { } usageError)
        {
            Console.Error.WriteLine($"Error: {usageError}");
            DisplayHelp(parserResult);
            return ExitCodes.UsageError;
        }

        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        var command = new ValidateCommand(Console.Out, Console.Error, httpClient, TimeProvider.System);
        return await command.RunAsync(options);
    }

    private static void DisplayHelp<T>(ParserResult<T> result)
    {
        var helpText = HelpText.AutoBuild(result, h => h, e => e);
        Console.WriteLine(helpText);
    }
}
