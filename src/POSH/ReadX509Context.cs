using System.Collections.Generic;
using System.Linq;
using Org.X509Crypto;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsCommunications.Read, nameof(X509Context))]
    [OutputType(typeof(X509AliasDescription))]
    public class ReadX509Context : Cmdlet
    {
        private X509Context Context;

        [Parameter(Position = 0, HelpMessage = "The X509Context from which to list existing X509Aliases and/or encryption certificates. Acceptable values are \"user\" and \"system\"")]
        [Alias("Context", "X509Context", "StoreLocation", "CertStore", "CertStoreLocation", "Store")]
        public string Location { get; set; }

        [Parameter(Position = 1, HelpMessage = "If $True, certificates that are not currently assigned to an X509Alias will also be included in the output. Default select is $False")]
        public bool All { get; set; } = false;

        private List<X509AliasDescription> Result = new List<X509AliasDescription>();

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

            Context = X509Context.Select(Location, false);

            var Aliases = Context.GetAliases(Constants.DoNotIncludeIfCertNotFound);
            Aliases.ForEach(p => Result.Add(new X509AliasDescription(p)));

            var AssignedThumbprints = Aliases.Select(p => p.Certificate.Thumbprint.ToUpper()).ToList();

            if (All)
            {
                using (var Store = new X509Store(Context.Location))
                {
                    Store.Open(OpenFlags.ReadOnly);
                    foreach (X509Certificate2 Cert in Store.Certificates)
                    {
                        if (!AssignedThumbprints.Contains(Cert.Thumbprint.ToUpper()))
                        {
                            Result.Add(new X509AliasDescription(Cert));
                        }
                    }
                }
            }
        }
    }
}
