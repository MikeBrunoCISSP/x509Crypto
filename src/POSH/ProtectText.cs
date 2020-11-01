using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.X509Crypto;
using System.Management.Automation;
using System.Security.Policy;

namespace X509CryptoPOSH
{
    #region Protect-Secret

    [Cmdlet(VerbsSecurity.Protect, "Secret")]
    public class ProtectText : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = @"The X509Context-bound X509Alias with which to protect the text. Use New-Alias or Get-Alias cmdlet to create.")]
        public ContextedAlias Alias { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The text expression to be encrypted")]
        [Alias("Text", "String")]
        public string Expression { get; set; } = string.Empty;

        [Parameter(HelpMessage = "Set to true if you'd like to allow overwriting an existing secret in the X509Alias.")]
        public bool Overwrite { get; set; } = false;

        [Parameter(HelpMessage = "The identifier under which to store the encrypted secret (used for retrieval)")]
        [Alias("SecretName", "Identifier")]
        public string Secret { get; set; } = string.Empty;

        private string Result = string.Empty;

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            DoWork();
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            WriteObject(Result);
        }

        private void DoWork()
        {

            if (!string.IsNullOrEmpty(Secret))
            {
                Alias.Alias.AddSecret(Secret, Expression, false);
                Alias.Alias.Commit();
                Console.WriteLine($"Secret {Secret.InQuotes()} added to {nameof(X509Alias)} {Alias.Alias.Name.InQuotes()} in the {Alias.Context.Name} {nameof(X509Context)}");
                Result = Alias.Alias.GetSecret(Secret);
            }
            else
            {
                Result = Alias.Alias.EncryptText(Expression);
            }
        }
    }

    #endregion

    #region Unprotect-Secret

    [Cmdlet(VerbsSecurity.Unprotect, "Text")]
    public class UnprotectText : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = @"The X509Context-bound X509Alias with which to protect the text. Use New-Alias or Get-Alias cmdlet to create.")]
        public ContextedAlias Alias { get; set; }

        [Parameter(HelpMessage = "The text expression to be encrypted. May not be combined with \"-Secret\"")]
        [Alias("Text", "Ciphertext", "EncryptedText")]
        public string Expression { get; set; } = string.Empty;

        [Parameter(HelpMessage = "The identifier under which the encrypted secret is stored within the X509Alias. May not be combined with \"-Expression\"")]
        [Alias("SecretName", "Identifier")]
        public string Secret { get; set; } = string.Empty;

        private string Result = string.Empty;

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            DoWork();
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            WriteObject(Result);
        }

        private void DoWork()
        {
            if (string.IsNullOrEmpty(Expression) ^ string.IsNullOrEmpty(Secret))
            {

                if (!string.IsNullOrEmpty(Secret))
                {
                    Result = Alias.Alias.RecoverSecret(Secret);
                }
                else
                {
                    Result = Alias.Alias.DecryptText(Expression);
                }
            }
            else
            {
                throw new X509CryptoException("Either the \"-Secret\" or the  \"-Expression\" must be defined, but not both.");
            }
        }
    }

    #endregion
}
