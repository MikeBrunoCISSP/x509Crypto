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
        private X509Context context;
        private bool contextSet;

        private string name;
        private bool nameSet;

        [Parameter(ValueFromPipeline = true, HelpMessage = "The X509Context from which to list existing X509Aliases.")]
        public X509Context Context
        {
            get
            {
                return context;
            }
            set
            {
                context = value;
                contextSet = true;
            }
        }

        [Parameter(HelpMessage = "The name of the X509Context in which to list existing X509Aliases. Acceptable values are \"user\" and \"system\"")]
        public string Name
        {
            get
            {
                return name;
            }
            set
            {
                name = value;
                nameSet = true;
            }
        }

        [Parameter(HelpMessage = "If set to true, certificates that are not currently assigned to an X509Alias will also be included in the output")]
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
            if (!(contextSet ^ nameSet))
            {
                throw new InvalidParametersException(nameof(Context), nameof(Name));
            }

            if (nameSet)
            {
                Context = X509Context.Select(Name, false);
            }

            var Aliases = Context.GetAliases(Constants.DoNotIncludeIfCertNotFound);
            Aliases.ForEach(p => Result.Add(new X509AliasDescription(p)));

            var AssignedThumbprints = Aliases.Select(p => p.Certificate.Thumbprint.ToUpper()).ToList();
            using (var Store = new X509Store(Context.Location))
            {
                Store.Open(OpenFlags.ReadOnly);
                foreach(X509Certificate2 Cert in Store.Certificates)
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
