using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Org.X509Crypto.Dto;

/// <summary>
/// X509Certificate2 Data Transfer Object.
/// </summary>
public class CertificateDto {
    public CertificateDto(X509Certificate2 cert) {
        Certificate = cert;
        Thumbprint = cert.Thumbprint.ToLower();
        Subject = cert.Subject;
        NotAfter = cert.NotAfter;
    }
    /// <summary>
    /// The certificate as an <see cref="X509Certificate2"/> object
    /// </summary>
    public X509Certificate2 Certificate { get; set; }
    /// <summary>
    /// The certificate thumbprint.
    /// </summary>
    public string Thumbprint { get; set; }
    /// <summary>
    /// The certificate subject.
    /// </summary>
    public string Subject { get; set; }
    /// <summary>
    /// The certificate expiration date.
    /// </summary>
    public DateTime NotAfter { get; set; }

    public Byte[] EncryptKey(byte[] plaintextKey, RSAEncryptionPadding padding) {
        using RSA rsa = Certificate.GetRSAPublicKey();
        return rsa.Encrypt(plaintextKey, padding);
    }

    public Byte[] DecryptKey(byte[] encryptedKey, RSAEncryptionPadding padding) {
        using RSA rsa = Certificate.GetRSAPrivateKey();
        return rsa.Decrypt(encryptedKey, padding);
    }
}
