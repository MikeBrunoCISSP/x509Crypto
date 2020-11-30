using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;
using Org.X509Crypto;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsData.Import, nameof(X509Alias))]
    [OutputType(typeof(X509Alias))]
    public class ImportX509Alias : PSCmdlet
    {
        private string path;

        [Parameter(Position = 0, Mandatory = true, HelpMessage = @"The path to the file where the X509Alias is stored")]
        public string Path
        {
            get
            {
                return path;
            }
            set
            {
                if (System.IO.Path.IsPathRooted(value))
                {
                    path = value;
                }
                else
                {
                    path = new FileInfo(System.IO.Path.Combine(SessionState.Path.CurrentFileSystemLocation.Path, value)).FullName;
                }
            }
        }

        [Parameter(Position = 1, Mandatory = true, HelpMessage = "The X509Context in which to import the X509Alias. Acceptable values are \"user\" and \"system\"")]
        [Alias("Context", "X509Context", "StoreLocation", "CertStore", "CertStoreLocation", "Store")]
        public string Location { get; set; }

        [Parameter(Position = 2, HelpMessage = @"The name under which to register this X509Alias")]
        [Alias(@"Alias", nameof(X509Alias))]
        public string Name { get; set; } = string.Empty;

        private X509Alias Result;

        [Parameter(HelpMessage = "If $True, if an existing X509Alias with the same name already exists in the X509Context specified for \"Location\", it will be overwritten. Default selection is $False")]
        public SwitchParameter Overwrite { get; set; } = false;

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
            var Context = X509Context.Select(Location, true);
            var AliasToImport = X509Alias.Import(Path, Context, Name);
            if (!Overwrite && X509Alias.AliasExists(AliasToImport))
            {
                throw new X509AliasAlreadyExistsException(AliasToImport);
            }
            AliasToImport.Commit();

            Util.ConsoleMessage($"{nameof(X509Alias)} {AliasToImport.Name.InQuotes()} has been successfully imported into the {Context.Name} {nameof(X509Context)} from the file {Path.InQuotes()}");

            if (!X509CryptoAgent.CertificateExists(AliasToImport))
            {
                Util.ConsoleWarning($"An encryption certificate with thumbprint {AliasToImport.Thumbprint.InQuotes()} could not be found in the {Context.Name} {nameof(X509Context)}. Ensure this certificate is installed on the system before using this alias.");
            }

            Result = AliasToImport;
        }
    }
}
