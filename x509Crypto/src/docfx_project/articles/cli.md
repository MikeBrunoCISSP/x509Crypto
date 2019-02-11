# Introducing the X509Crypto Command Line Utility

The X509Crypto Command Line Utility (CLI) is a companion tool to be used in conjunction with the X509Crypto class library.  It provides access to many of the core features of the class library without the need for you to write test programs to execute one-off tasks (such as encrypting a piece of text).

Click [Here](../downloads/X509Crypto_CLI_v1.0.1.zip) to download the X509Crypto CLI.

## Modes of operation

**Usage: X509Crypto.exe [COMMAND]**

|Command|Description|
|-------|-----------|
|*encrypt*|Encrypts the specified plaintext expression or file|
|*decrypt*|Decrypts the specified ciphertext expression or file|
|*reencrypt*|Encrypts the specified ciphertext expression or file using a different certificate|
|*import*|Imports a certificate and key pair from the specified PKCS#12 (.pfx) file|
|*export*|Exports a specified key pair and/or certificate from a specified certificate store|
|*list*|Lists the available encryption certificates in the specified certificate store|
|*makecert*|Create a new self-signed encryption certificate|

## Encryption Commands
Use the commands below to encrypt plaintext expressions and files.

### Encrypting Text Expressions

**Usage: X509Crypto.exe encrypt -text -thumb [cert thumbprint] -in [plaintext] { -store [CURRENTUSER|LOCALMACHINE] -out [path|clipboard] }**

|Parameter|Required?|Description|
|---------|---------|-----------|
|-thumb|yes|The thumbprint of the encryption certificate whose public key you wish to use to encrypt the text|
|-in|yes|The plaintext expression you wish to encrypt|
|store||the certificate store name where the encryption certificate is located<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|
|-out||Either the fully-qualified file path where you would like the ciphertext to be written, or **clipboard** if you'd like it to be written to the system clipboard. If this parameter is not specified, the output will be displayed on-screen|

### Encrypting Files

**Usage: X509Crypto.exe encrypt -file -thumb [cert thumbprint] -in [plaintext] { -store [CURRENTUSER|LOCALMACHINE] -out [path] -w}**

|Parameter|Required?|Description|
|---------|---------|-----------|
|-thumb|yes|The thumbprint of the encryption certificate whose public key you wish to use to encrypt the file|
|-in|yes|The fully-qualified path to the plaintext file you wish to encrypt<br><br>Both text and binary-type files are supported|
|store||the certificate store name where the encryption certificate is located<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|
|-out||The fully-qualified path to where you would like the resulting ciphertext file to be written.<br><br>If not specified, the file path specified for the *-in* parameter appended with a ".ctx" extension will be used.|
|-w||If the -w parameter is included in the command, and the file encryption is successful, the plaintext file will be scrubbed from disk|

## Decryption Commands
Use the commands below to decrypt ciphertext expressions and files.

### Decrypting Ciphertext Expressions

**Usage: X509Crypto.exe decrypt -text -thumb [cert thumbprint] -in [ciphertext] { -store [CURRENTUSER|LOCALMACHINE] -out [path|clipboard] }**

|Parameter|Required?|Description|
|---------|---------|-----------|
|-thumb|yes|The thumbprint of the encryption certificate whose private key will decrypt the ciphertext<br>(It must be the same certificate which was originally used for encryption)|
|-in|yes|The ciphertext expression you wish to decrypt|
|store||the certificate store name where the encryption certificate is located<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|
|-out||Either the fully-qualified file path where you would like the plaintext to be written, or **clipboard** if you'd like it to be written to the system clipboard. If this parameter is not specified, the output will be displayed on-screen|

### Decrypting Ciphertext Files

**Usage: X509Crypto.exe decrypt -file -thumb [cert thumbprint] -in [ciphertext] { -store [CURRENTUSER|LOCALMACHINE] -out [path] }**

|Parameter|Required?|Description|
|---------|---------|-----------|
|-thumb|yes|The thumbprint of the encryption certificate whose private key will decrypt the ciphertext<br>(It must be the same certificate which was originally used for encryption)|
|-in|yes|The fully-qualified path to the ciphertext file you wish to encrypt<br><br>Both text and binary-type files are supported|
|store||the certificate store name where the encryption certificate is located<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|
|-out||The fully-qualified path to where you would like the resulting ciphertext file to be written.<br><br>If not specified, the file path specified for the *-in* parameter appended with a ".ptx" extension will be used.|

## Re-Encryption Commands
Just like death and taxes, certificate expiration is a fact of life. This is especially true if you are using certificates that were issued from a real certification authority (and even if you're not, you should still replace a certificate every year or so in order to minimize the risk of key compromise!).  One of the challenges when replacing digital certificates is that the data encrypted by the old certificate public key must still remain available!  Luckily, this CLI provides a single command which allows you to swap the certificate that encrypts a plaintext expression or file.

### Re-encrypt Ciphertext Expressions

**Usage: X509Crypto.exe reencrypt -text -in ciphertext -oldthumb [old cert thumbprint] -newthumb [new cert thumbprint] {-oldstore [CURRENTUSER|LOCALMACHINE] -newstore [CURRENTUSER|LOCALMACHINE] -out [path|clipboard]}**

|Parameter|Required?|Description|
|---------|---------|-----------|
|-oldthumb|yes|The thumbprint of the old encryption certificate whose public key originally encrypted the text expression|
|-newthumb|yes|The thumbprint of the new encryption certificate whose public key will re-encrypt the text expression|
|-in|yes|The ciphertext expression you wish to re-encrypt|
|-oldstore||the certificate store name where the old encryption certificate is located<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|
|-newstore||the certificate store name where the replacement encryption certificate is located<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|
|-out||Either the fully-qualified file path where you would like the ciphertext to be written, or **clipboard** if you'd like it to be written to the system clipboard. If this parameter is not specified, the output will be displayed on-screen|

### Re-Encrypt Files

**Usage: X509Crypto.exe reencrypt -file -in ciphertext -oldthumb [old cert thumbprint] -newthumb [new cert thumbprint] {-oldstore [CURRENTUSER|LOCALMACHINE] -newstore [CURRENTUSER|LOCALMACHINE]}**

|Parameter|Required?|Description|
|---------|---------|-----------|
|-oldthumb|yes|The thumbprint of the old encryption certificate whose public key originally encrypted the file|
|-newthumb|yes|The thumbprint of the new encryption certificate whose public key will re-encrypt the file|
|-in|yes|The fully-qualified path to the ciphertext file you wish to re-encrypt|
|-oldstore||the certificate store name where the old encryption certificate is located<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|
|-newstore||the certificate store name where the replacement encryption certificate is located<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|

## Certificate-Related Commands
The commands below allow you to import and export certificates as well as create new self-signed certificates.

### Import A Certificate and Private Key

**Usage: X509Crypto.exe import -in [path] {-pass [password] -store [CURRENTUSER|LOCALMACHINE]}**

|Parameter|Required?|Description|
|---------|---------|-----------|
|-in|yes|The fully-qualified path to the PKCS #12 to be imported.<br>PKCS #12 files typically have a .pfx or .p12 file extension and contain a certificate bundled with it's corresponding private key.|
|-pass||The password which unlocks the private key contained within the PKCS #12 file.<br>If no password is specified, the private key is assumed to be unprotected.|
|store||the certificate store name where the encryption certificate and private is to be imported.<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|

### Export a Certificate

**Usage: X509Crypto.exe -thumb [cert thumbprint] export [-key|-nokey] -pass [password] -out [path] {-store [CURRENTUSER|LOCALMACHINE]}**

|Parameter|Required?|Description|
|---------|---------|-----------|
|-thumb|yes|The thumbprint of the encryption certificate you wish to export|
|-key<br>  or<br>-nokey||Indicates whether the private key should be exported along with the indicated certificate<br>If not specified, -nokey is the default selection|
|-pass|yes|The password to protect the PKCS#12 certificate/key bundle file<br>(Applicable only if the *-key* option is specified. Otherwise, this parameter is ignored)|
|-out|yes|The fully-qualified path where the exported certificate file should be written|
|store||the certificate store from which the encryption certificate/private key is to be exported.<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|

### Make a Self-Signed Certificate

**Usage: X509Crypto.exe makecert -subject [Certificate Subject] { -keylength [small|medium|large] -store [CURRENTUSER|LOCALMACHINE] -expires [years] }**

|Parameter|Required?|Description|
|---------|---------|-----------|
|-subject|yes|The subject (common name) that should be given to the certificate|
|-keylength||Indicates how large of a public key should be generated.<br><br>The following values are valid for this parameter: <ul><li>**small**<br>The public key will be 1024 bits</li><li>**medium**<br>The public key will be 2048 bits</li><li>**large**<br>The public key will be 4096 bits</li></ul><br>Note: the larger the public key length, the stronger the encryption, but the slower the performance.<br>The default selection for this option is *medium*|
|store||the certificate store into which the encryption certificate/private key should be installed once generated.<br><br>The following values are valid for this parameter: <ul><li>**CURRENTUSER**<br>The certificate store owned by the currently logged-on user</li><li>**LOCALMACHINE**<br>The certificate store owned by the SYSTEM account <br>(Note: Local administrative rights are typically required to access this store)</li></ul><br>The default selection for this option is CURRENTUSER|
|-expires||The number of years before the certificate should become invalid due to expiry<br>The default value for this option is *2*|

