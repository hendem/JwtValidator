using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator.Tests;

/// <summary>Tests for <see cref="KeyLoader"/>.</summary>
public class KeyLoaderTests
{
    /// <summary>Every JWKS entry is described, but only usable signing keys are loaded.</summary>
    [Fact]
    public void FromJwks_DescribesEveryEntry_IncludingOnesThatCannotBeUsed()
    {
        using var rsa = TestTokens.NewRsa();
        var jwks = TestTokens.Jwks(
            TestTokens.RsaJwk(rsa, "good"),
            """{"kty":"RSA","kid":"encryption","use":"enc","n":"AQAB","e":"AQAB"}""");

        var keySet = KeyLoader.FromJwks(jwks, "jwks");

        Assert.Equal(["good", "encryption"], keySet.Entries.Select(e => e.Kid));
        var key = Assert.Single(keySet.Keys);
        Assert.Equal("good", key.KeyId);
    }

    /// <summary>JSON without a <c>keys</c> array is rejected.</summary>
    [Fact]
    public void FromJwks_WithoutKeysArray_Throws()
    {
        Assert.Throws<InvalidDataException>(() => KeyLoader.FromJwks("""{"kty":"RSA"}""", "jwks"));
    }

    /// <summary>JSON that isn't an object is rejected with the same error as a missing <c>keys</c> array.</summary>
    /// <param name="json">The JWKS text.</param>
    [Theory]
    [InlineData("[]")]
    [InlineData("\"just a string\"")]
    [InlineData("42")]
    public void FromJwks_WhenRootIsNotAnObject_Throws(string json)
    {
        Assert.Throws<InvalidDataException>(() => KeyLoader.FromJwks(json, "jwks"));
    }

    /// <summary>Text that isn't JSON is rejected.</summary>
    [Fact]
    public void FromJwks_WithInvalidJson_Throws()
    {
        Assert.ThrowsAny<JsonException>(() => KeyLoader.FromJwks("not json", "jwks"));
    }

    /// <summary>Loading a private key PEM keeps only the public key.</summary>
    [Fact]
    public void FromRsaPem_WithPrivateKey_KeepsOnlyThePublicKey()
    {
        using var rsa = TestTokens.NewRsa();

        var keySet = KeyLoader.FromRsaPem(rsa.ExportRSAPrivateKeyPem(), "pem");

        var key = Assert.IsType<RsaSecurityKey>(Assert.Single(keySet.Keys));
        Assert.Null(key.Parameters.D);
        Assert.Equal(rsa.ExportParameters(false).Modulus, key.Parameters.Modulus);
    }

    /// <summary>Text that doesn't contain a PEM key is rejected.</summary>
    [Fact]
    public void FromRsaPem_WithoutPem_Throws()
    {
        Assert.Throws<ArgumentException>(() => KeyLoader.FromRsaPem("not a pem", "pem"));
    }

    /// <summary>Non-RSA keys have no RSA parameters.</summary>
    [Fact]
    public void GetRsaParameters_ReturnsNullForNonRsaKeys()
    {
        using var ecdsa = TestTokens.NewEcdsa(ECCurve.NamedCurves.nistP256);

        Assert.Null(KeyLoader.GetRsaParameters(new ECDsaSecurityKey(ecdsa)));
    }
}
