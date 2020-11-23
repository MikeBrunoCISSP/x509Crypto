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

    [Cmdlet(VerbsSecurity.Protect, "Secret")]
    public class ProtectSecret : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = @"The X509Context-bound X509Alias with which to protect the text. Use New-Alias or Get-Alias cmdlet to create.")]
        [Alias(@"Alias", @"X509Alias")]
        public ContextedAlias Id { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The text expression to be encrypted")]
        [Alias("Text", "Expression")]
        public string Input { get; set; } = string.Empty;

        [Parameter(HelpMessage = "Set to true if you'd like to allow overwriting an existing secret in the X509Alias.")]
        public bool Overwrite { get; set; } = false;

        [Parameter(HelpMessage = "The identifier under which to store the encrypted secret (used for retrieval)")]
        [Alias("SecretName", "Identifier")]
        public string Secret { get; set; } = string.Empty;

        private string Result = string.Empty;

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            DoWork();
            WriteObject(Result);
        }

        private void DoWork()
        {

            if (!string.IsNullOrEmpty(Secret))
            {
                Id.Alias.AddSecret(Secret, Input, false);
                Id.Alias.Commit();
                Console.WriteLine($"Secret {Secret.InQuotes()} added to {nameof(X509Alias)} {Id.Alias.Name.InQuotes()} in the {Id.Context.Name} {nameof(X509Context)}");
                Result = Id.Alias.GetSecret(Secret);
            }
            else
            {
                Result = Id.Alias.EncryptText(Input);
            }
        }
    }
}
