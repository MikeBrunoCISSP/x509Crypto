using Org.X509Crypto;
using System.Management.Automation;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsCommunications.Read, @"Secret")]
    public class UnprotectText : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = @"The X509Context-bound X509Alias with which to protect the text. Use New-Alias or Get-Alias cmdlet to create.")]
        public ContextedAlias Alias { get; set; }

        [Parameter(HelpMessage = "The text expression to be encrypted. May not be combined with \"-Secret\"")]
        [Alias("Ciphertext", "Expression")]
        public string Input { get; set; } = string.Empty;

        [Parameter(HelpMessage = "The identifier under which the encrypted secret is stored within the X509Alias. May not be combined with \"-Expression\"")]
        [Alias("Secret", "Identifier")]
        public string Property { get; set; } = string.Empty;

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
            if (string.IsNullOrEmpty(Input) ^ string.IsNullOrEmpty(Property))
            {

                if (!string.IsNullOrEmpty(Property))
                {
                    Result = Alias.Alias.RecoverSecret(Property);
                }
                else
                {
                    Result = Alias.Alias.DecryptText(Input);
                }
            }
            else
            {
                throw new X509CryptoException("Either the \"-Secret\" or the  \"-Expression\" must be defined, but not both.");
            }
        }
    }
}
