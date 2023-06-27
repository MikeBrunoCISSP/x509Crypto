using System;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Org.X509Crypto.Dto;

/// <summary>
/// X509Certificate2 Data Transfer Object.
/// </summary>
[DataContract]
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
    [DataMember]
    public X509Certificate2 Certificate { get; set; }
    /// <summary>
    /// The certificate thumbprint.
    /// </summary>
    [DataMember]
    public string Thumbprint { get; set; }
    /// <summary>
    /// The certificate subject.
    /// </summary>
    [DataMember]
    public string Subject { get; set; }
    /// <summary>
    /// The certificate expiration date.
    /// </summary>
    [DataMember]
    public DateTime NotAfter { get; set; }

    public RSA GetPublicKey() => Certificate.GetRSAPublicKey();
    public RSA GetPrivateKey() => Certificate.GetRSAPrivateKey();

    public Byte[] EncryptKey(byte[] plaintextKey, RSAEncryptionPadding padding) {
        using RSA rsa = Certificate.GetRSAPublicKey();
        return rsa.Encrypt(plaintextKey, padding);
    }

    public Byte[] DecryptKey(byte[] encryptedKey, RSAEncryptionPadding padding) {
        using RSA rsa = Certificate.GetRSAPrivateKey();
        return rsa.Decrypt(encryptedKey, padding);
    }
}
