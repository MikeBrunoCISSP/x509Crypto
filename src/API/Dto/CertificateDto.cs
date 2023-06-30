using System;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;

namespace Org.X509Crypto.Dto;

/// <summary>
/// X509Certificate2 Data Transfer Object.
/// </summary>
[DataContract]
public class CertificateDto {
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

    public static CertificateDto FromX509Certificate2(X509Certificate2 cert) {
        return new CertificateDto {
            Certificate = cert,
            Thumbprint = cert.Thumbprint,
            Subject = cert.Subject,
            NotAfter = cert.NotAfter
        };
    }
}
