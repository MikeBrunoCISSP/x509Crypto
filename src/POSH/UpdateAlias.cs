using Org.X509Crypto;
using System;
using System.Management.Automation;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsData.Update, nameof(X509Alias))]
    [OutputType(typeof(ContextedAlias))]
    public class UpdateAlias : Cmdlet
    {
        private string context = string.Empty;
        private bool contextSet = false;
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = "The source X509Alias from which to move all protected secrets")]
        [Alias(@"X509Alias")]
        public ContextedAlias Alias { get; set; }

        [Parameter(HelpMessage = "The X509Context where the new encryption certificate exists. If not specified, the X509Context of the entry for \"Alias\" will be used. Acceptable entries are \"user\" and \"system\".")]
        [Alias(@"NewContext")]
        public string Context
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

        [Parameter(Mandatory = true, HelpMessage = "The thumbprint of the new encryption certificate")]
        public string Thumbprint { get; set; }

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            DoWork();
            WriteObject(Alias);
        }

        private void DoWork()
        {
            X509Context OldContext,
                        NewContext;

            OldContext = Alias.Context;
            if (contextSet)
            {
                NewContext = X509Context.Select(Context, false);
            }
            else
            {
                NewContext = Alias.Context;
            }

            if (!X509CryptoAgent.CertificateExists(Thumbprint, NewContext))
            {
                throw new X509CryptoCertificateNotFoundException(Thumbprint, NewContext);
            }
            Alias.Alias.ReEncrypt(Thumbprint, NewContext);
            Alias.Alias.Commit();
            Console.WriteLine($"{nameof(X509Alias)} {Alias.Alias.Name} successfully updated. Now using encryption certificate with thumbprint {Thumbprint} from the {NewContext.Name} {nameof(X509Context)}");
        }
    }
}
