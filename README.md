# JWT validator

A command-line tool that helps troubleshoot JWTs and explains why a token does or doesn't validate.
It checks the signature against a JWKS (URL, file or inline JSON) or an RSA public key in PEM format.
Optionally it also checks the issuer, audience and lifetime, and it prints a readable breakdown of the token and keys.

Supported algorithms: RS256/384/512, PS256/384/512 and ES256/384/512.

## Usage

```
JwtValidator (--jwt <token> | --jwt-file <path>)
             (--jwks-url <url> | --jwks-file <path> | --jwks-json <json> | --rsa-key-file <path>)
             [--issuer <iss>] [--audience <aud>] [--validate-lifetime] [--clock-skew <seconds>]
             [--manual] [--verbose]
```

| Option | Description |
| --- | --- |
| `-j`, `--jwt` | The JWT to validate. |
| `--jwt-file` | The file path of the JWT. Leading and trailing whitespace is ignored. |
| `-u`, `--jwks-url` | The URL of the JWKS. |
| `--jwks-json` | The JWKS payload. |
| `--jwks-file` | The file path of a JWKS file. |
| `--rsa-key-file` | The file path of the RSA key in PEM format. A private key PEM also works; only the public part is used. |
| `--issuer` | Require the token's `iss` claim to equal this value. |
| `--audience` | Require the token's `aud` claim to contain this value. |
| `--validate-lifetime` | Reject tokens that are expired or not yet valid (`exp`/`nbf`). |
| `--clock-skew` | Allowed clock skew in seconds when validating the lifetime (default: 300). |
| `--manual` | Verify the RSA signature (RS256/384/512) directly with `System.Security.Cryptography` instead of the token handler. Checks the signature only. |
| `-v`, `--verbose` | Also print the decoded header and payload, and the full error detail on failure. |
| `--help` | Display the help screen. |
| `--version` | Display version information. |

Provide exactly one token source and exactly one key source.
Issuer, audience and lifetime are not checked unless you ask for them, so by default the tool answers "was this token signed by one of these keys?"

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The token is valid. |
| `1` | The token is invalid: malformed, bad signature, or a failed claim check. |
| `2` | Usage or input error: missing or conflicting options, unreadable file, invalid JWKS/PEM, or the JWKS URL could not be fetched. |

### Example

```
> JwtValidator --jwt-file token.jwt --jwks-url https://issuer.example/oauth2/jwks
Token
  alg: RS256   kid: (none)   typ: JWT
  iss: issuer.example
  sub: user
  aud: my-api
  iat: 2024-02-22 18:30:04Z (2 years ago)
  exp: 2024-02-22 18:45:04Z (expired 2 years ago; not enforced without --validate-lifetime)
Keys (JWKS from https://issuer.example/oauth2/jwks)
  kid: 2775c10b   kty: EC   alg: -   use: -
  kid: 5601c05a   kty: RSA   alg: RS256   use: sig
  The token has no kid; every key will be tried.
Result: token is valid (signature verified with kid '5601c05a').
```

The output flags common problems:
- a `kid` in the token that isn't in the key set
- JWKS entries that couldn't be used (for example, malformed `n`/`e` values)
- expired or not-yet-valid tokens

## Building and testing

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```
dotnet build JwtValidator.slnx
dotnet test --solution JwtValidator.slnx
dotnet run --project src/JwtValidator -- --help
```

The repository layout:

```
src/JwtValidator/          the command-line tool
tests/JwtValidator.Tests/  xUnit tests (keys and tokens are generated in the tests)
```
