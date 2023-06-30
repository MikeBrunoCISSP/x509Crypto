using System;
using System.Runtime.Serialization;

namespace Org.X509Crypto.Dto;
[Serializable]
public class EncryptedFileDto {
    [DataMember]
    public string OriginalFileName { get; set; }
    [DataMember]
    public string OriginalExtension { get; set; }
    [DataMember]
    public EncryptedSecretDto Data { get; set; }
}
