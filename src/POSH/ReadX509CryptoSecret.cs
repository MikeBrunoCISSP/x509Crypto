using Org.X509Crypto;
using System.Management.Automation;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsCommunications.Read, @"X509CryptoSecret")]
    [OutputType(typeof(string))]
    public class UnprotectText : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = @"The X509Alias with which to protect the text.")]
        [Alias(nameof(X509Alias))]
        public X509Alias Alias { get; set; }

        [Parameter(HelpMessage = "The ciphertext expression to be decrypted. May not be combined with \"-Id\"")]
        [Alias("Ciphertext", "Expression")]
        public string Input { get; set; } = string.Empty;

        [Parameter(HelpMessage = "The identifier under which the encrypted secret is stored within the X509Alias. May not be combined with \"-Expression\"")]
        [Alias("Secret", "SecretName", "Identifier")]
        public string Id { get; set; } = string.Empty;

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
            if (string.IsNullOrEmpty(Input) ^ string.IsNullOrEmpty(Id))
            {

                if (!string.IsNullOrEmpty(Id))
                {
                    Result = Alias.RecoverSecret(Id);
                }
                else
                {
                    Result = Alias.DecryptText(Input);
                }
            }
            else
            {
                throw new X509CryptoException("Either the \"-Secret\" or the  \"-Expression\" must be defined, but not both.");
            }
        }
    }
}
