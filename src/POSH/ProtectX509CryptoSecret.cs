using System;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH {

    [Cmdlet(VerbsSecurity.Protect, "X509CryptoSecret")]
    [OutputType(typeof(bool))]
    public class ProtectX509CryptoSecret : Cmdlet {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = @"The X509Alias with which to protect the text. Use New-Alias or Get-Alias cmdlet to create.")]
        [Alias(nameof(X509Alias))]
        public X509Alias Alias { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The text expression to be encrypted")]
        [Alias("Text", "Expression")]
        public string Input { get; set; } = string.Empty;

        [Parameter(HelpMessage = "If enabled and there is already a secret contained in the specified X509Alias stored under the name specified for '-Id' the existing secret will be overwritten.")]
        public SwitchParameter Overwrite { get; set; } = false;

        [Parameter(Mandatory = true, HelpMessage = "The identifier under which to store the encrypted secret (used for retrieval)")]
        [Alias("Secret", "SecretName", "Identifier")]
        public string Id { get; set; } = string.Empty;

        private bool Result = false;

        protected override void BeginProcessing() {
            base.BeginProcessing();
        }

        protected override void ProcessRecord() {
            base.ProcessRecord();
            DoWork();
            WriteObject(Result);
        }

        private void DoWork() {
            Alias.AddSecret(Id, Input, Overwrite);
            Alias.Commit();
            Console.WriteLine($"Secret '{Id}' added to {nameof(X509Alias)} '{Alias.Name}' in the {Alias.Context.Name} {nameof(X509Context)}");
            Result = true;
        }
    }
}
