using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace JwtValidator.Tests;

public class KeyLoaderTests
{
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

    [Fact]
    public void FromJwks_WithoutKeysArray_Throws()
    {
        Assert.Throws<InvalidDataException>(() => KeyLoader.FromJwks("""{"kty":"RSA"}""", "jwks"));
    }

    [Fact]
    public void FromJwks_WithInvalidJson_Throws()
    {
        Assert.ThrowsAny<JsonException>(() => KeyLoader.FromJwks("not json", "jwks"));
    }

    [Fact]
    public void FromRsaPem_WithPrivateKey_KeepsOnlyThePublicKey()
    {
        using var rsa = TestTokens.NewRsa();

        var keySet = KeyLoader.FromRsaPem(rsa.ExportRSAPrivateKeyPem(), "pem");

        var key = Assert.IsType<RsaSecurityKey>(Assert.Single(keySet.Keys));
        Assert.Null(key.Parameters.D);
        Assert.Equal(rsa.ExportParameters(false).Modulus, key.Parameters.Modulus);
    }

    [Fact]
    public void FromRsaPem_WithoutPem_Throws()
    {
        Assert.Throws<ArgumentException>(() => KeyLoader.FromRsaPem("not a pem", "pem"));
    }

    [Fact]
    public void GetRsaParameters_ReturnsNullForNonRsaKeys()
    {
        using var ecdsa = TestTokens.NewEcdsa(ECCurve.NamedCurves.nistP256);

        Assert.Null(KeyLoader.GetRsaParameters(new ECDsaSecurityKey(ecdsa)));
    }
}
