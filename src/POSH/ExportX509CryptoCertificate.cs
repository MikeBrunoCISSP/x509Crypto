using System.IO;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH {
    [Cmdlet(VerbsData.Export, "X509CryptoCertificate")]
    [OutputType(typeof(FileInfo))]
    public class ExportX509CryptoCertificate : PSCmdlet {
        private X509Alias alias = null;
        private bool aliasSet = false;

        private X509Context Context = null;
        private bool contextSet = false;

        private string thumbprint = string.Empty;
        private bool thumbprintSet = false;

        private string path = string.Empty;

        [Parameter(ValueFromPipeline = true, HelpMessage = "The source X509Alias from which to export the encryption certificate. Not to be used with the '-Location' and '-Thumbprint' parameters")]
        [Alias(@"X509Alias")]
        public X509Alias Alias {
            get {
                return alias;
            }
            set {
                alias = value;
                aliasSet = true;
            }
        }

        [Parameter(HelpMessage = "The X509Context from which to export the certificate. Acceptable values are 'user' and 'system'. Must be paired with the '-Thumbprint' parameter. Not to be used with the '-Alias' parameter")]
        [Alias("Context", "X509Context", "StoreLocation", "CertStore", "CertStoreLocation", "Store")]
        public string Location {
            get {
                return Context.Name;
            }
            set {
                Context = X509Context.Select(value);
                contextSet = true;
            }
        }

        [Parameter(HelpMessage = "The thumbprint of the encryption certificate to export. Must be paired with the '-Location' parameter. Not to be used with the 'Alias' parameter")]
        public string Thumbprint {
            get {
                return thumbprint;
            }
            set {
                thumbprint = value;
                thumbprintSet = true;
            }
        }

        [Parameter(Mandatory = true, HelpMessage = "The path in which to write the PKCS#12 cert/key bundle file.")]
        public string Path {
            get {
                return path;
            }
            set {
                if (System.IO.Path.IsPathRooted(value)) {
                    path = value;
                } else {
                    path = new FileInfo(System.IO.Path.Combine(SessionState.Path.CurrentFileSystemLocation.Path, value)).FullName;
                    if (!System.IO.Path.GetExtension(path).Matches(FileExtensions.Pfx)) {
                        path = $"{path}{FileExtensions.Pfx}";
                    }
                }
            }
        }

        [Parameter(HelpMessage = "If enabled & an existing file is found in the path specified for '-Path', it will be deleted without a warning.")]
        public SwitchParameter Overwrite { get; set; } = false;

        FileInfo Result = null;

        protected override void BeginProcessing() {
            base.BeginProcessing();
        }

        protected override void ProcessRecord() {
            base.ProcessRecord();
            DoWork();
            WriteObject(Result);
        }

        private void DoWork() {
            if (aliasSet) {
                if (contextSet || thumbprintSet) {
                    throw new ParameterBindingException($"Either the '{nameof(Alias)}' parameter or the '{nameof(Location)}' and '{nameof(Thumbprint)}' parameters must be set.");

                }
            } else {
                if (!(contextSet && thumbprintSet)) {
                    throw new ParameterBindingException($"Either the '{nameof(Alias)}' parameter or the '{nameof(Location)}' and '{nameof(Thumbprint)}' parameters must be set.");

                }
            }

            if (!aliasSet) {
                Alias = new X509Alias(string.Empty, Thumbprint, Context, false);
            }

            if (!System.IO.Path.GetExtension(Path).Matches(FileExtensions.Pfx)) {
                path = $"{path}{FileExtensions.Pfx}";
            }

            if (File.Exists(Path)) {
                if (Overwrite || Util.WarnConfirm($"The specified file {Path} already exists. Do you wish to overwrite it?", Constants.Affirm)) {
                    X509Utils.DeleteFile(Path, confirmDelete: true);
                } else {
                    throw new X509CryptoException($"The specified file {Path} already exists.");
                }
            }

            var Password = Util.GetPassword(@"Enter a strong password (needed to unlock the .pfx file)", Constants.MinimumPasswordLength, true);
            X509CryptoAgent.ExportPFX(Alias.Thumbprint, Alias.Context, Path, Password.ToUnSecureString());
            Util.ConsoleMessage($"Encryption certificate with thumbprint {Alias.Thumbprint} from the {Alias.Context.Name} {nameof(X509Context)} has been exported to the file {Path}");
            Result = new FileInfo(Path);
        }
    }
}
