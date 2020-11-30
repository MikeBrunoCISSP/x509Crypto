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

    [Cmdlet(VerbsSecurity.Protect, "X509CryptoSecret")]
    [OutputType(typeof(bool))]
    public class ProtectX509CryptoSecret : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = @"The X509Context-bound X509Alias with which to protect the text. Use New-Alias or Get-Alias cmdlet to create.")]
        [Alias(nameof(X509Alias))]
        public X509Alias Alias { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The text expression to be encrypted")]
        [Alias("Text", "Expression")]
        public string Input { get; set; } = string.Empty;

        [Parameter(HelpMessage = "Set to true if you'd like to allow overwriting an existing secret in the X509Alias.")]
        public SwitchParameter Overwrite { get; set; } = false;

        [Parameter(Mandatory = true, HelpMessage = "The identifier under which to store the encrypted secret (used for retrieval)")]
        [Alias("Secret", "SecretName", "Identifier")]
        public string Id { get; set; } = string.Empty;

        private bool Result = false;

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
            Alias.AddSecret(Id, Input, Overwrite);
            Alias.Commit();
            Console.WriteLine($"Secret {Id.InQuotes()} added to {nameof(X509Alias)} {Alias.Name.InQuotes()} in the {Alias.Context.Name} {nameof(X509Context)}");
            Result = true;
        }
    }
}
