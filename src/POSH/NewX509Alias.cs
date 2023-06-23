using System;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH {
    #region New-X509Alias

    [Cmdlet(VerbsCommon.New, nameof(X509Alias))]
    [OutputType(typeof(X509Alias))]
    public class NewX509Alias : Cmdlet {
        [Parameter(Mandatory = true, HelpMessage = "The desired name for the X509Alias")]
        [Alias("Alias", nameof(X509Alias))]
        public string Name { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The X509Context in which to create the alias. Acceptable values are 'user' and 'system'")]
        [Alias("Context", "X509Context", "StoreLocation", "CertStore", "CertStoreLocation", "Store")]
        public string Location { get; set; }

        [Parameter(HelpMessage = "The thumbprint of the encryption certificate. If not specified, a new self-signed encryption certificate will be automatically generated within the specified X509Context.")]
        public string Thumbprint { get; set; } = string.Empty;

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
            if (string.IsNullOrEmpty(Thumbprint)) {
                Thumbprint = MakeCert();
            }

            X509Alias Alias = new X509Alias(Name, Thumbprint, context, true);
            Alias.Commit();
            Result = Alias;
            Console.WriteLine($@"New alias '{Name}' committed to '{context.Name}' {nameof(X509Context)}
  Thumbprint: {Alias.Thumbprint}");
        }

        private string MakeCert() {
            string commonName = string.Empty;
            string thumbprint = string.Empty;
            if (context == X509Context.UserFull) {
                commonName = Environment.UserName;
            } else {
                commonName = Environment.MachineName;
            }

            context.MakeCert(commonName, 2048, 10, out thumbprint);
            return thumbprint;
        }
    }

    #endregion
}
