using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator.Tests;

public class TokenValidatorTests
{
    [Fact]
    public async Task RsaToken_WithPemKey_IsValid()
    {
        using var rsa = TestTokens.NewRsa();
        var jwt = TestTokens.CreateToken(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var outcome = await TokenValidator.ValidateAsync(jwt, keySet.Keys, TestTokens.NoClaimChecks);

        Assert.True(outcome.IsValid, outcome.Error);
    }

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

    // Regression test: the original implementation imported every JWKS key into one RSA instance,
    // so only the last RSA key in the set was ever used.
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

    public static TheoryData<string, string> EcAlgorithms => new()
    {
        { SecurityAlgorithms.EcdsaSha256, "P-256" },
        { SecurityAlgorithms.EcdsaSha384, "P-384" },
        { SecurityAlgorithms.EcdsaSha512, "P-521" },
    };

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

    [Fact]
    public async Task UnsignedToken_IsInvalid()
    {
        using var rsa = TestTokens.NewRsa();
        var unsigned = new JsonWebTokenHandler().CreateToken("""{"sub":"test-user"}""");
        var keySet = KeyLoader.FromRsaPem(rsa.ExportSubjectPublicKeyInfoPem(), "pem");

        var outcome = await TokenValidator.ValidateAsync(unsigned, keySet.Keys, TestTokens.NoClaimChecks);

        Assert.False(outcome.IsValid);
    }

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
