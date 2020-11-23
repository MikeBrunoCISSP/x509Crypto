using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsSecurity.Unprotect, nameof(X509Alias))]
    [OutputType(typeof(ProtectedSecret))]
    public class UnprotectX509Alias : Cmdlet
    {
        private ContextedAlias calias = null;
        private bool caliasSet = false;

        [Parameter(HelpMessage = "The X509Alias from which to list secrets")]
        public string Name { get; set; } = string.Empty;

        [Parameter(HelpMessage = "The X509Context in which the encryption certificate exists. Acceptable values are \"user\" and \"system\"")]
        [Alias("X509Context", "Store")]
        public string Context { get; set; } = string.Empty;

        [Parameter(ValueFromPipeline = true, HelpMessage = "An X509Alias object created using either the \"Get-X509Alias\" or the \"New-X509Alias\" cmdlet")]
        public ContextedAlias Alias
        {
            get
            {
                return calias;
            }
            set
            {
                caliasSet = true;
                calias = value;
            }
        }

        private X509Alias alias;
        private X509Context context;
        private List<ProtectedSecret> Result = new List<ProtectedSecret>();

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
            if (!(caliasSet ^ (!string.IsNullOrEmpty(Name) && !string.IsNullOrEmpty(Context))))
            {
                throw new X509CryptoException($"Either the {nameof(Alias).InQuotes()} or both the {nameof(Name).InQuotes()} and {nameof(Context).InQuotes()} must be set.");
            }

            if (caliasSet)
            {
                alias = calias.Alias;
            }
            else
            {
                context = X509Context.Select(Context, false);
                alias = new X509Alias(Name, context);
            }

            Dictionary<string, string> Dict = alias.DumpSecrets(SecretDumpFormat.Dictionary, true);
            foreach(KeyValuePair<string, string> Pair in Dict)
            {
                Result.Add(new ProtectedSecret(Pair));
            }
        }
    }
}
