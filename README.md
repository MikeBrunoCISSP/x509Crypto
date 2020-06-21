X509Crypto allows you to encrypt and recover text expression using X509 digital certificates and key pairs. The latest release eliminates the need to include any secrets (even in an encrypted form) in your source code, configuration files or database.

## Encrypting a secret using X509Crypto

#### Use the [X509Crypto Commandline Interface](https://github.com/MikeBrunoCISSP/x509Crypto/tree/master/zip) (CLI) to generate a new encryption certificate and key pair 
Note: Certification Authority-issued certificates are supported as well as long as they include the *Key Encipherment* key usage extension

```
>x509crypto.exe
X509Crypto> makecert -context user -keysize medium -alias myvault

Certificate with thumbprint B31FE7E7AE5229F8186782742CF579197FA859FD was added to the user X509Context

X509Crypto>
```

The **context** argument can be either *user* or *system* depending on the context in which the application which will need to recover the secret runs in.

The **keyzise** argument can be *small*, *medium*, or *large*. The larger the key pair, the higher the security, but performance will be slower.

#### Use the **AddAlias** command in the CLI to bind your newly-created certificate to an *X509Alias*. 
For demonstration purposes, we will create an *X509Alias* called "myvault".

```
X509Crypto> addalias -name myvault -context user -thumb B31FE7E7AE5229F8186782742CF579197FA859FD

New X509Alias "myvault" was created in the user X509Context using certificate with thumbprint "B31FE7E7AE5229F8186782742CF579197FA859FD"

X509Crypto>
```

#### Use the **Encrypt** CLI command to add a secret to your new *X509Alias*

```
X509Crypto> encrypt -text -alias myvault -context user -secret apikey -in "80EAF03248965AC2B78090"

Secret apikey has been added to X509Alias myvault in the user X509Context

X509Crypto>
```

The **-text** argument indicates that we're encrypting a text expression (as opposed to a file)

The **-alias** and **-context** arguments point to the *X509Alias* that we created in step 2.

The **-secret** argument assigns an identifier to the secret we're about to encrypt so that it can be recovered from the *X509Alias* later. In this example, we've established a secret named "apikey"

The **-in** argument indicates the text expression to be encrypted.

The contents of the *X509Alias* are saved as a base64-encoded file:

```
C:\Users\mikeb>type c:\users\mikeb\AppData\Local\X509Crypto\myvault.xca
eyJDb250ZXh0Ijp7fSwiTmFtZSI6...
```

If you remove the encoding, you'll find an object in json format. The secrets contained in the *X509Alias* remain in an encrypted form, of course:

```
{
   "Context":{

   },
   "Name":"myvault",
   "Secrets":[
      {
         "Key":"apikey",
         "Value":"AAEAABAAAAAHjn58kwkbA4SDinqSVjWHY..."
      }
   ],
   "Thumbprint":"B31FE7E7AE5229F8186782742CF579197FA859FD"
}
```

#### Reference the secret in your program

Once you have an *X509Alias* established with your secret(s) added, it is trivial to retreive them in your program with the Org.X509Crypto nuget package installed:

```
using Org.X509Crypto;

namespace SampleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var Alias = new X509Alias(@"myvault", X509Context.UserReadOnly);
            var apiKey = Alias.RecoverSecret(@"apikey");
        }
    }
}
```