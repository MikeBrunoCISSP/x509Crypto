using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using Org.X509Crypto;
using Org.X509Crypto.Dto;
using Org.X509Crypto.Services;

namespace X509CryptoPOSH {
    [Cmdlet(VerbsCommunications.Read, nameof(X509Context))]
    [OutputType(typeof(X509AliasDescription))]
    public class ReadX509Context : Cmdlet {
        static readonly CertService _certService = new CertService();
        private X509Context Context;

        [Parameter(Mandatory = true, Position = 0, HelpMessage = "The X509Context from which to list existing X509Aliases and/or encryption certificates. Acceptable values are 'user' and 'system'")]
        [Alias("Context", "X509Context", "StoreLocation", "CertStore", "CertStoreLocation", "Store")]
        public string Location { get; set; }

        [Parameter(Position = 1, HelpMessage = "If enabled, certificates that are not currently assigned to an X509Alias will also be included in the output.")]
        public SwitchParameter All { get; set; } = false;

        private List<X509AliasDescription> Result = new List<X509AliasDescription>();

        protected override void BeginProcessing() {
            base.BeginProcessing();

        }

        protected override void ProcessRecord() {
            base.ProcessRecord();
            DoWork();
            WriteObject(Result);
        }

        private void DoWork() {

            Context = X509Context.Select(Location);

            var Aliases = Context.GetAliases(Constants.DoNotIncludeIfCertNotFound);
            Aliases.ForEach(p => Result.Add(new X509AliasDescription(p)));

            var AssignedThumbprints = Aliases.Select(p => p.Thumbprint.ToUpper()).ToList();

            if (All) {
                List<CertificateDto> certs = _certService.GetAllCertificates(Context);
                foreach (var cert in certs.Where(cert => !AssignedThumbprints.Contains(cert.Thumbprint.ToUpper()))) {
                    Result.Add(new X509AliasDescription(cert));
                }
            }
        }
    }
}
