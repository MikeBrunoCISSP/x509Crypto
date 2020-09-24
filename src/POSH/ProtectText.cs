using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.X509Crypto;
using System.Management.Automation;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsSecurity.Protect, "Text")]
    public class ProtectText : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, HelpMessage = "The X509Alias which points to the encryption certificate")]
        public string Alias { get; set; } = string.Empty;

        [Parameter(Mandatory = true, HelpMessage = "The X509Context in which the encryption certificate exists. Acceptable values are \"user\" and \"system\"")]
        [Alias("X509Context", "Store")]
        public string Context { get; set; } = string.Empty;

        [Parameter(Mandatory = true, HelpMessage = "The text expression to be encrypted")]
        [Alias("Text", "String")]
        public string Expression { get; set; } = string.Empty;

        [Parameter(HelpMessage = "Set to true if you'd like to allow overwriting an existing secret in the X509Alias.")]
        public bool Overwrite { get; set; } = false;

        [Parameter(HelpMessage = "The identifier under which to store the encrypted secret (used for retrieval)")]
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
            context = X509Context.Select(Context, false);
            alias = new X509Alias(Alias, context);

            if (!string.IsNullOrEmpty(Secret))
            {
                alias.AddSecret(Secret, Expression, false);
                alias.Commit();
                Console.WriteLine($"Secret {Secret.InQuotes()} added to {nameof(X509Alias)} {Alias.InQuotes()} in the {context.Name} {nameof(X509Context)}");
                Result = alias.GetSecret(Secret);
            }
            else
            {
                Result = alias.EncryptText(Expression);
            }
        }
    }
}
