using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;
using Org.X509Crypto;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsLifecycle.Install, @"X509CryptoCertificate")]
    [OutputType(typeof(X509Alias))]
    public class InstallX509CryptoCertificate : PSCmdlet
    {
        private string path = string.Empty;

        [Parameter(Mandatory = true, HelpMessage = "The path to the PKCS#12 file conaining the encryption certificate and private key")]
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
                    if (!File.Exists(path)) {
                        throw new FileNotFoundException($"File does not exist: {path}");
                    }
                }
            }
        }

        [Parameter(Mandatory = true, HelpMessage = "The X509Context in which to install the encryption certificate. Acceptable values are \"user\" and \"system\"")]
        [Alias("Context", "X509Context", "StoreLocation", "CertStore", "CertStoreLocation", "Store")]
        public string Location { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The name of a new X509Alias in which to associate this encryption certificate")]
        [Alias(@"Alias", nameof(X509Alias))]
        public string Name { get; set; }

        [Parameter(HelpMessage = "If enabled and an existing X509Alias with the name indicated for \"-Name\" is found, it will be overwritten")]
        public SwitchParameter Overwrite { get; set; } = false;

        private X509Alias Result;

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
            Console.WriteLine($"Path: {Path}");
            var Context = X509Context.Select(Location, true);
            var Alias = Context.GetAliases(true).FirstOrDefault(p => p.Name.Matches(Name));
            if (null != Alias)
            {
                if (!Overwrite || !Util.WarnConfirm($"An existing {nameof(X509Alias)} with the name {Name.InQuotes()} exists in the {Context.Name} {nameof(X509Context)}. OK to overwrite?", Constants.Affirm))
                {
                    throw new X509CryptoException($"Could not import the certificate. An {nameof(X509Alias)} with the name {Name.InQuotes()} exists in the {Context.Name} {nameof(X509Context)}");
                }
            }

            var PfxPassword = Util.GetPassword($"Enter the password to unlock {System.IO.Path.GetFileName(Path).InQuotes()}", 0);
            var thumbprint = X509Utils.InstallCert(Path, PfxPassword, Context);
            StringBuilder Expression = new StringBuilder($"Added encryption certificate to the {Context.Name} {nameof(X509Context)}. \r\nCertificate Thumbprint: {thumbprint}");

            if (null != Alias && Alias.HasCert(Context))
            {
                Alias.ReEncrypt(thumbprint, Context);
                Expression.AppendLine($"\r\nAll secrets contained in the existing {nameof(X509Alias)} {Alias.Name.InQuotes()} have been re-encrypted using the new certificate.");
            }
            else
            {
                Alias = new X509Alias(Name, thumbprint, Context, false);
                Alias.Commit();
                Expression.Append($"\r\n             {nameof(X509Alias)}: {Name}");
            }

            Util.ConsoleMessage(Expression.ToString());
            Result = Alias;
        }
    }
}
