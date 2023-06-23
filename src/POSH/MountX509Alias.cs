using System;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH {

    [Cmdlet(VerbsData.Mount, nameof(X509Alias))]
    [OutputType(typeof(X509Alias))]
    public class MountX509Alias : Cmdlet {

        [Parameter(Mandatory = true, HelpMessage = "The name for the X509Alias to retrieve")]
        [Alias("Alias", nameof(X509Alias))]
        public string Name { get; set; }

        [Parameter(HelpMessage = "The name of X509Context where the X509Alias exists. Acceptable values are 'user' and 'system'")]
        [Alias("Context", "X509Context", "StoreLocation", "CertStore", "CertStoreLocation", "Store")]
        public string Location { get; set; }

        private X509Context context;
        private X509Alias Result;

        protected override void BeginProcessing() {
            base.BeginProcessing();
        }

        protected override void ProcessRecord() {
            base.ProcessRecord();
            DoWork();
            WriteObject(Result);
        }

        private void DoWork() {

            context = X509Context.Select(Location);
            X509Alias Alias = new X509Alias(Name, context);
            Result = Alias;
            Console.WriteLine($"Alias '{Name}' has been loaded from the '{context.Name}' {nameof(X509Context)}");
        }
    }
}
