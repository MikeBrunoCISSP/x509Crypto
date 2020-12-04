## Introducing the X509Crypto Data Encryption API
X509Crypto obfuscates most of the complexity involved with protecting data in .NET applications using encryption. It allows you to encrypt and recover text expressions and files using X509 digital certificates and key pairs. The latest release utilizes CNG and features an all-new companion PowerShell module! X509Crypto eliminates the need to include any secrets (even in an encrypted form) in your source code, configuration files or database tables.

## API Documentation
The full X509Crypto API documentation can be found [here](https://x509crypto.org/api/Org.X509Crypto.html)

## X509Crypto makes it easy to encrypt and recover text expressions in your .NET projects:

#### 1. Install the [X509Crypto PowerShell module](https://www.powershellgallery.com/packages/X509Crypto/1.1.0): 
The X509Crypto PowerShell module can be installed from the PowerShell Gallery.

```
> Install-Module X509Crypto

# ...Or if you are not an admin:
> Install-Module X509Crypto -Scope CurrentUser
```

#### 2. Use the **New-X509Alias** cmdlet: 
This cmdlet instantiates a new X509Crypto Alias (which stores encrypted secrets). In this example, we don't have a previously-existing certificate and key pair, so we'll execute the cmdlet without the *-Thumbprint* parameter, which will trigger the creation of a new certificate that will be automatically associated with this X509Alias.

```
> $Alias = New-X509Alias -Name myvault -Location user

New alias "myvault" committed to "user" X509Context
Thumbprint: B31FE7E7AE5229F8186782742CF579197FA859FD
```

#### 3. Use the **Protect-X509CryptoSecret** PowerShell cmdlet to encrypt a secret
In this example, we'll be storing an API authentication key in the X509Alias "myvault".  Secrets are stored in X509Aliases as key/value pairs, so we'll assign the identifier "apikey" to this new secret.
```
> $Alias | Protect-X509CryptoSecret -Id apkikey -Input '80EAF03248965AC2B78090'

Secret "apkikey" added to X509Alias "myvault4" in the user X509Context
```

#### 3. Reference the secret in your program

Once you have an *X509Alias* established with your secret(s) added, it is trivial to retreive them in your program with the [Org.X509Crypto nuget package](https://www.nuget.org/packages/Org.X509Crypto/1.3.0) installed:

```
using Org.X509Crypto;

namespace SampleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Instantiate the X509Alias object, referencing the "myvault" alias in the CurrentUser context
            using (var Alias = new X509Alias(@"myvault", X509Context.UserReadOnly))
            {
                // Recover the plaintext secret "apikey" as plaintext in a string variable
                string apiKey = Alias.RecoverSecret(@"apikey");

                // Use the secret before leaving the "using" block so that it will be garbage-collected promptly
                MyApi.Connect(apiKey);
            }
        }
    }
}
```

<br>

Note that anything that can be done using the X509Crypto PowerShell module or the [X509Crypto commandline utility](https://x509crypto.org/articles/cli.html) can also be accomplished directly in the API.

Reach out to the project Owner: [Mike Bruno](mailto:mikebrunocissp@gmail.com) with any questions or comments.