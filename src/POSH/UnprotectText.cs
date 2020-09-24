using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsSecurity.Unprotect, "Text")]
    public class UnprotectText : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, HelpMessage = "The X509Alias which points to the encryption certificate")]
        public string Alias { get; set; } = string.Empty;

        [Parameter(Mandatory = true, HelpMessage = "The X509Context in which the encryption certificate exists. Acceptable values are \"user\" and \"system\"")]
        [Alias("X509Context", "Store")]
        public string Context { get; set; } = string.Empty;

        [Parameter(HelpMessage = "The text expression to be encrypted. May not be combined with \"-Secret\"")]
        [Alias("Text", "Ciphertext", "EncryptedText")]
        public string Expression { get; set; } = string.Empty;

        [Parameter(HelpMessage = "The identifier under which the encrypted secret is stored within the X509Alias. May not be combined with \"-Expression\"")]
        [Alias("SecretName", "Identifier")]
        public string Secret { get; set; } = string.Empty;

        private X509Alias alias;
        private X509Context context;
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
                context = X509Context.Select(Context, false);
                alias = new X509Alias(Alias, context);

                if (!string.IsNullOrEmpty(Secret))
                {
                    Result = alias.RecoverSecret(Secret);
                }
                else
                {
                    Result = alias.DecryptText(Expression);
                }
            }
            else
            {
                throw new X509CryptoException("Either the \"-Secret\" or the  \"-Expression\" must be defined, but not both.");
            }
        }
    }
}
