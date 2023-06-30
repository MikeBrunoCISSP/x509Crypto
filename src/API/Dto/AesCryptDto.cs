using System;
using System.Security.Cryptography;

namespace Org.X509Crypto.Dto;
internal class AesCryptDto : IDisposable {
    private const int KEY_SIZE    = 256;
    private const int BLOCK_SIZE  = 128;

    public AesManaged Aes { get; set; }
    public ICryptoTransform Transform { get; set; }

    public static AesCryptDto CreateEncryptor() {
        var payLoad = new AesCryptDto {
            Aes = new AesManaged {
                KeySize = KEY_SIZE,
                BlockSize = BLOCK_SIZE,
                Mode = CipherMode.CBC
            }
        };
        payLoad.Transform = payLoad.Aes.CreateEncryptor();
        return payLoad;
    }

    public static AesCryptDto CreateDecryptor(byte[] symmetricKey, byte[] iv) {
        var payLoad = new AesCryptDto {
            Aes = new AesManaged {
                KeySize = KEY_SIZE,
                BlockSize = BLOCK_SIZE,
                Mode = CipherMode.CBC,
                Key = symmetricKey,
                IV = iv
            }
        };
        payLoad.Transform = payLoad.Aes.CreateDecryptor();
        return payLoad;
    }

    public void Dispose() {
        Transform.Dispose();
        Aes.Dispose();
    }
}
