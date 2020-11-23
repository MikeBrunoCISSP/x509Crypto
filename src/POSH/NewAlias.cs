using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.X509Crypto;
using System.Management.Automation;
using System.ComponentModel;

namespace X509CryptoPOSH
{
    #region New-X509Alias

    [Cmdlet(VerbsCommon.New, nameof(X509Alias))]
    public class NewAlias : Cmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "The desired name for the X509Alias")]
        [Alias("N","Alias")]
        public string Name { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The X509Context in which to create the alias. Acceptable values are \"user\" and \"system\"")]
        [Alias("X509Context", "Store")]
        public string Context { get; set; }

        [Parameter(HelpMessage = "The thumbprint of the encryption certificate. If not specified, a new encryption certificate will be automatically generated within the specified X509Context.")]
        public string Thumbprint { get; set; } = string.Empty;

        private X509Context context;

        private ContextedAlias Result;

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
            context = X509Context.Select(Context, true);
            if (string.IsNullOrEmpty(Thumbprint))
            {
                Thumbprint = MakeCert();
            }

            X509Alias Alias = new X509Alias(Name, Thumbprint, context, true);
            Result = new ContextedAlias(Alias, context);
            Result.CheckExists(mustNotExist: true);
            Alias.Commit();
            Console.WriteLine($"New alias {Name.InQuotes()} committed to {context.Name.InQuotes()} {nameof(X509Context)}\r\nThumbprint: {Alias.Thumbprint}");
        }

        private string MakeCert()
        {
            string commonName = string.Empty;
            string thumbprint = string.Empty;
            if (context == X509Context.UserFull)
            {
                commonName = Environment.UserName;
            }
            else
            {
                commonName = Environment.MachineName;
            }

            context.MakeCertWorker(commonName, 2048, 10, out thumbprint);
            return thumbprint;
        }
    }

    #endregion
}
