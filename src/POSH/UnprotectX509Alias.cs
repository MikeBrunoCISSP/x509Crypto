using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsSecurity.Unprotect, "X509Alias")]
    public class UnprotectX509Alias : Cmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "The X509Alias from which to list secrets")]
        public string Alias { get; set; } = string.Empty;

        [Parameter(Mandatory = true, HelpMessage = "The X509Context in which the encryption certificate exists. Acceptable values are \"user\" and \"system\"")]
        [Alias("X509Context", "Store")]
        public string Context { get; set; } = string.Empty;

        private X509Alias alias;
        private X509Context context;
        private string Result;

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
            Result = alias.DumpSecrets(true);
        }
    }
}
