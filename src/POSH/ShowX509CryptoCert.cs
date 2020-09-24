using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.X509Crypto;
using System.Management.Automation;

namespace x509CryptoPOSH
{
    [Cmdlet(VerbsCommon.Show, "X509CryptoCert")]
    public class ShowX509CryptoCert : Cmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "The X509Context in which to list existing certificates suitable for use with the X509Crypto library. Acceptable values are \"user\" and \"system\"")]
        [Alias("X509Context", "Store")]
        public string Context { get; set; }

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            DoWork();
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
        }

        private void DoWork()
        {
            X509Context context = X509Context.Select(Context, false);
            Console.WriteLine(X509CryptoAgent.ListCerts(context));
        }
    }
}
