using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Org.X509Crypto.Dto;
internal class KeyPairDto : IDisposable {
    internal KeyPairDto(CertificateDto certDto) {
        PublicKey = certDto.Certificate.GetRSAPublicKey();
        if (PublicKey is null) {
            throw new X509CryptoException($"The public key associated with certificate '{certDto.Thumbprint}' could not be loaded.");
        }

        PrivateKey = certDto.Certificate.GetRSAPrivateKey();
        if (PrivateKey is null) {
            throw new X509CryptoException($"The private key associated with certificate '{certDto.Thumbprint}' could not be loaded.");
        }
    }
    internal RSA PublicKey { get; }
    internal RSA PrivateKey { get; }

    public void Dispose() {
        PublicKey?.Dispose();
        PrivateKey?.Dispose();
    }
}
