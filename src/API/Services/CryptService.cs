using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.X509Crypto.Dto;

namespace Org.X509Crypto.Services;
public class CryptService {
    private const int KEY_SIZE    = 256;
    private const int BLOCK_SIZE  = 128;
    private const int BYTE_SIZE   = 4;
    private const int BLOCK_BYTES = 16;

    public EncryptedSecretDto EncryptText(RSA publicKey, string secret) {
        using AesManaged aes = new AesManaged();
        aes.KeySize = KEY_SIZE;
        aes.BlockSize = BLOCK_SIZE;
        aes.Mode = CipherMode.CBC;

        using ICryptoTransform transform = aes.CreateEncryptor();
        return new EncryptedSecretDto {
            EncryptedKey = publicKey.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256),
            InitializationVector = aes.IV,
            Data = encryptData(transform, secret)
        };
    }

    public string DecryptText(RSA privateKey, EncryptedSecretDto dto) {
        string payLoad = string.Empty;
        byte[] symmetricKey = privateKey.Decrypt(dto.EncryptedKey, RSAEncryptionPadding.OaepSHA384);

        using AesManaged aes = new AesManaged {
            KeySize = KEY_SIZE,
            BlockSize = BLOCK_SIZE,
            Mode = CipherMode.CBC,
            Key = symmetricKey,
            IV = dto.InitializationVector
        };
        using MemoryStream inStream = new MemoryStream(dto.Data);
        inStream.Seek(0, SeekOrigin.Begin);
        using ICryptoTransform transform = aes.CreateDecryptor(symmetricKey, dto.InitializationVector);
        using MemoryStream outStream = new MemoryStream();
        int offSet = 0;
        byte[] data = new byte[BLOCK_BYTES];
        using var cryptStream = new CryptoStream(outStream, transform, CryptoStreamMode.Write);
        int count = 0;
        do {
            count = inStream.Read(data, 0, BLOCK_BYTES);
            offSet += count;
            cryptStream.Write(data, 0, count);
        } while (count > 0);

        cryptStream.FlushFinalBlock();
        outStream.Flush();
        outStream.Position = 0;

        using var reader = new StreamReader(outStream);
        payLoad = reader.ReadToEnd();
        cryptStream.Close();
        outStream.Close();

        return payLoad;
    }

    byte[] encryptData(ICryptoTransform transform, string secret) {
        using MemoryStream memStream = new MemoryStream();

        using CryptoStream cryptStream = new CryptoStream(memStream, transform, CryptoStreamMode.Write);
        byte[] blockTaken = new byte[BLOCK_BYTES];

        using MemoryStream inStream = new MemoryStream(Encoding.UTF8.GetBytes(secret), false);
        int count;
        do {
            count = inStream.Read(blockTaken, 0, BLOCK_SIZE);
            cryptStream.Write(blockTaken, 0, count);
        } while (count > 0);
        inStream.Close();

        cryptStream.FlushFinalBlock();
        cryptStream.Close();
        return memStream.ToArray();
    }

    byte[] decryptData(AesManaged aes, byte[] data) {
        using ICryptoTransform transform = aes.CreateEncryptor();

    }
}
