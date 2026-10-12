using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator.Tests;

/// <summary>Tests for <see cref="TokenValidator"/>.</summary>
public class TokenValidatorTests
{
    /// <summary>An RS256 token validates against the matching RSA public key loaded from PEM.</summary>
    [Fact]
    public async Task RsaToken_WithPemKey_IsValid()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var outcome = await TokenValidator.ValidateAsync(jwt, keySet.Keys, TestTokens.NoClaimChecks);

        Assert.True(outcome.IsValid, outcome.Error);
    }

    /// <summary>An RS256 token validates against a JWKS and the outcome reports the signing key's kid.</summary>
    [Fact]
    public async Task RsaToken_WithJwks_IsValid()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256);
        var keySet = KeyLoader.FromJwks(TestTokens.Jwks(TestTokens.RsaJwk(rsa, "k1")), "jwks");

        var outcome = await TokenValidator.ValidateAsync(jwt, keySet.Keys, TestTokens.NoClaimChecks);

        Assert.True(outcome.IsValid, outcome.Error);
        Assert.Equal("k1", outcome.SigningKey?.KeyId);
    }

    /// <summary>
    /// A JWKS with several RSA keys validates a token signed by any of them, with or without a kid,
    /// using both the token handler and manual validation.
    /// </summary>
    /// <remarks>
    /// Regression test: the original implementation imported every JWKS key into one RSA instance,
    /// so only the last RSA key in the set was ever used.
    /// </remarks>
    /// <param name="signerIndex">The position of the signing key in the JWKS.</param>
    /// <param name="tokenHasKid">Whether the token header includes the signing key's kid.</param>
    [Theory]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(0, false)]
    [InlineData(1, false)]
    public async Task Jwks_WithSeveralRsaKeys_UsesTheSigningKeyWhereverItIs(int signerIndex, bool tokenHasKid)
    {
        RSA[] keys = [TestTokens.NewRsa(), TestTokens.NewRsa(), TestTokens.NewRsa()];
        try
        {
            var signer = new RsaSecurityKey(keys[signerIndex]) { KeyId = tokenHasKid ? $"k{signerIndex}" : null };
            var jwt = TestTokens.CreateToken(signer, SecurityAlgorithms.RsaSha256);
            var jwks = TestTokens.Jwks(keys.Select((k, i) => TestTokens.RsaJwk(k, $"k{i}")).ToArray());
            var keySet = KeyLoader.FromJwks(jwks, "jwks");

            var outcome = await TokenValidator.ValidateAsync(jwt, keySet.Keys, TestTokens.NoClaimChecks);
            var manualOutcome = TokenValidator.ValidateSignatureManually(new JsonWebToken(jwt), keySet.Keys);

            Assert.True(outcome.IsValid, outcome.Error);
            Assert.True(manualOutcome.IsValid, manualOutcome.Error);
            Assert.Equal($"k{signerIndex}", manualOutcome.SigningKey?.KeyId);
        }
        finally
        {
            foreach (var key in keys)
            {
                key.Dispose();
            }
        }
    }

    /// <summary>The ECDSA algorithms and their matching JWK curve names.</summary>
    public static TheoryData<string, string> EcAlgorithms => new()
    {
        { SecurityAlgorithms.EcdsaSha256, "P-256" },
        { SecurityAlgorithms.EcdsaSha384, "P-384" },
        { SecurityAlgorithms.EcdsaSha512, "P-521" },
    };

    /// <summary>ES256, ES384 and ES512 tokens validate against an EC key in a JWKS.</summary>
    /// <param name="algorithm">The ECDSA signing algorithm.</param>
    /// <param name="crv">The JWK curve name that goes with the algorithm.</param>
    [Theory]
    [MemberData(nameof(EcAlgorithms))]
    public async Task EcToken_WithJwks_IsValid(string algorithm, string crv)
    {
        var curve = crv switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var ecdsa = TestTokens.NewEcdsa(curve);
        var jwt = TestTokens.CreateToken(new ECDsaSecurityKey(ecdsa) { KeyId = "ec" }, algorithm);
        var keySet = KeyLoader.FromJwks(TestTokens.Jwks(TestTokens.EcJwk(ecdsa, crv, "ec")), "jwks");

        var outcome = await TokenValidator.ValidateAsync(jwt, keySet.Keys, TestTokens.NoClaimChecks);

        Assert.True(outcome.IsValid, outcome.Error);
    }

    /// <summary>RS384, RS512 and PS256 tokens validate, not only RS256.</summary>
    /// <param name="algorithm">The RSA signing algorithm.</param>
    [Theory]
    [InlineData(SecurityAlgorithms.RsaSha384)]
    [InlineData(SecurityAlgorithms.RsaSha512)]
    [InlineData(SecurityAlgorithms.RsaSsaPssSha256)]
    public async Task OtherRsaAlgorithms_AreSupported(string algorithm)
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa), algorithm);
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var outcome = await TokenValidator.ValidateAsync(jwt, keySet.Keys, TestTokens.NoClaimChecks);

        Assert.True(outcome.IsValid, outcome.Error);
    }

    /// <summary>A token signed with a different key is rejected by both validation paths.</summary>
    [Fact]
    public async Task WrongKey_IsInvalid()
    {
        using var signer = TestTokens.NewRsa();
        using var other = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(signer), SecurityAlgorithms.RsaSha256);
        var keySet = KeyLoader.FromRsaPem(other.ExportSubjectPublicKeyInfoPem(), "pem");

        var outcome = await TokenValidator.ValidateAsync(jwt, keySet.Keys, TestTokens.NoClaimChecks);
        var manualOutcome = TokenValidator.ValidateSignatureManually(new JsonWebToken(jwt), keySet.Keys);

        Assert.False(outcome.IsValid);
        Assert.False(manualOutcome.IsValid);
    }

    /// <summary>A token whose payload was changed after signing is rejected by both validation paths.</summary>
    [Fact]
    public async Task TamperedPayload_IsInvalid()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        var parts = jwt.Split('.');
        var forgedPayload = Base64UrlEncoder.Encode("""{"sub":"admin"}""");
        var tampered = $"{parts[0]}.{forgedPayload}.{parts[2]}";
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var outcome = await TokenValidator.ValidateAsync(tampered, keySet.Keys, TestTokens.NoClaimChecks);
        var manualOutcome = TokenValidator.ValidateSignatureManually(new JsonWebToken(tampered), keySet.Keys);

        Assert.False(outcome.IsValid);
        Assert.False(manualOutcome.IsValid);
    }

    /// <summary>An unsigned (alg none) token is rejected.</summary>
    [Fact]
    public async Task UnsignedToken_IsInvalid()
    {
        using var rsa = TestTokens.NewRsa();
        var unsigned = new JsonWebTokenHandler().CreateToken("""{"sub":"test-user"}""");
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var outcome = await TokenValidator.ValidateAsync(unsigned, keySet.Keys, TestTokens.NoClaimChecks);

        Assert.False(outcome.IsValid);
    }

    /// <summary>An expired token passes by default and fails with an expiry error when the lifetime is validated.</summary>
    [Fact]
    public async Task ExpiredToken_IsOnlyRejectedWhenLifetimeIsValidated()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(
            new RsaSecurityKey(rsa),
            SecurityAlgorithms.RsaSha256,
            expires: DateTime.UtcNow.AddHours(-1),
            notBefore: DateTime.UtcNow.AddHours(-2));
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var withoutLifetime = await TokenValidator.ValidateAsync(jwt, keySet.Keys, TestTokens.NoClaimChecks);
        var withLifetime = await TokenValidator.ValidateAsync(
            jwt, keySet.Keys, TestTokens.NoClaimChecks with { ValidateLifetime = true });

        Assert.True(withoutLifetime.IsValid, withoutLifetime.Error);
        Assert.False(withLifetime.IsValid);
        Assert.IsType<SecurityTokenExpiredException>(withLifetime.Exception);
    }

    /// <summary>A token whose nbf is in the future fails when the lifetime is validated.</summary>
    [Fact]
    public async Task NotYetValidToken_IsRejectedWhenLifetimeIsValidated()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(
            new RsaSecurityKey(rsa),
            SecurityAlgorithms.RsaSha256,
            expires: DateTime.UtcNow.AddHours(2),
            notBefore: DateTime.UtcNow.AddHours(1));
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var outcome = await TokenValidator.ValidateAsync(
            jwt, keySet.Keys, TestTokens.NoClaimChecks with { ValidateLifetime = true });

        Assert.False(outcome.IsValid);
        Assert.IsType<SecurityTokenNotYetValidException>(outcome.Exception);
    }

    /// <summary>When an issuer is given, a matching issuer passes and a different one fails.</summary>
    [Fact]
    public async Task Issuer_IsCheckedWhenProvided()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var matching = await TokenValidator.ValidateAsync(
            jwt, keySet.Keys, TestTokens.NoClaimChecks with { Issuer = TestTokens.Issuer });
        var mismatched = await TokenValidator.ValidateAsync(
            jwt, keySet.Keys, TestTokens.NoClaimChecks with { Issuer = "https://someone-else.example" });

        Assert.True(matching.IsValid, matching.Error);
        Assert.False(mismatched.IsValid);
        Assert.IsType<SecurityTokenInvalidIssuerException>(mismatched.Exception);
    }

    /// <summary>When an audience is given, a matching audience passes and a different one fails.</summary>
    [Fact]
    public async Task Audience_IsCheckedWhenProvided()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var matching = await TokenValidator.ValidateAsync(
            jwt, keySet.Keys, TestTokens.NoClaimChecks with { Audience = TestTokens.Audience });
        var mismatched = await TokenValidator.ValidateAsync(
            jwt, keySet.Keys, TestTokens.NoClaimChecks with { Audience = "another-audience" });

        Assert.True(matching.IsValid, matching.Error);
        Assert.False(mismatched.IsValid);
        Assert.IsType<SecurityTokenInvalidAudienceException>(mismatched.Exception);
    }

    /// <summary>Manual validation accepts RS256, RS384 and RS512 tokens signed by the key.</summary>
    /// <param name="algorithm">The RSA PKCS#1 signing algorithm.</param>
    [Theory]
    [InlineData(SecurityAlgorithms.RsaSha256)]
    [InlineData(SecurityAlgorithms.RsaSha384)]
    [InlineData(SecurityAlgorithms.RsaSha512)]
    public void ManualValidation_AcceptsRsaPkcs1Algorithms(string algorithm)
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa), algorithm);
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var outcome = TokenValidator.ValidateSignatureManually(new JsonWebToken(jwt), keySet.Keys);

        Assert.True(outcome.IsValid, outcome.Error);
    }

    /// <summary>Manual validation rejects non-RSA algorithms and names the algorithm in the error.</summary>
    [Fact]
    public void ManualValidation_RejectsUnsupportedAlgorithm()
    {
        using var ecdsa = TestTokens.NewEcdsa(ECCurve.NamedCurves.nistP256);
        var jwt = TestTokens.CreateToken(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256);

        var outcome = TokenValidator.ValidateSignatureManually(new JsonWebToken(jwt), []);

        Assert.False(outcome.IsValid);
        Assert.Contains("ES256", outcome.Error);
    }
}
