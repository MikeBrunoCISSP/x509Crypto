using System;
using System.IO;
using System.Management.Automation;
using System.Text;
using Org.X509Crypto;

namespace X509CryptoPOSH {
    [Cmdlet(VerbsSecurity.Protect, @"File")]
    [OutputType(typeof(FileInfo))]
    public class ProtectFile : PSCmdlet {
        private string path = string.Empty;
        private string output = string.Empty;
        private bool outputSet = false;

        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = "The X509Alias to use for encryption")]
        [Alias(nameof(X509Alias))]
        public X509Alias Alias { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The path of the file to encrypt")]
        public string Path {
            get {
                return path;
            }
            set {
                if (System.IO.Path.IsPathRooted(value)) {
                    path = value;
                } else {
                    path = new FileInfo(System.IO.Path.Combine(SessionState.Path.CurrentFileSystemLocation.Path, value)).FullName;
                }

                if (!File.Exists(path)) {
                    throw new FileNotFoundException($"'{path}': File not found");
                }
            }
        }

        [Parameter(HelpMessage = "The path to which to write the encrypted file. If not specified, the name of the file indicated for '-Path' will be appended with a '.ctx' extension")]
        public string Output {
            get {
                return output;
            }
            set {
                if (System.IO.Path.IsPathRooted(value)) {
                    output = value;
                } else {
                    output = new FileInfo(System.IO.Path.Combine(SessionState.Path.CurrentFileSystemLocation.Path, value)).FullName;
                }
                outputSet = true;
            }
        }

        [Parameter(HelpMessage = "The number of times to write over the disk sectors where the plaintext file exists. If not specified, the plaintext file will not be deleted or erased.")]
        [Alias(@"Wipe")]
        public int Erase { get; set; } = 0;

        [Parameter(HelpMessage = "If enabled, no warning will be displayed before the plaintext file specified for '-Path' is wiped from disk. Not appliable if '-Erase' is not defined")]
        public SwitchParameter Quiet { get; set; } = false;

        [Parameter(HelpMessage = "If enabled, should a file already exist under the same path as specified/inferred for 'Output', it will be replaced.")]
        public SwitchParameter Overwrite { get; set; } = false;

        private FileInfo Result = null;

        protected override void BeginProcessing() {
            base.BeginProcessing();
        }

        protected override void ProcessRecord() {
            base.ProcessRecord();
            DoWork();
            WriteObject(Result);
        }

        private void DoWork() {
            int wipeTimesToWrite = 0;

            if (!outputSet) {
                output = $"{Path}{FileExtensions.Ciphertext}";
            }
            Util.CheckForExistingFile(Output, Overwrite, nameof(Overwrite), PoshSyntax.True);

            if (Erase > 0) {
                if (Quiet || Util.WarnConfirm($"You have included the {nameof(Erase)} argument. This will permanently delete the file '{Path}' from disk.", Constants.Affirm)) {
                    wipeTimesToWrite = Erase;
                }
            }

            Alias.EncryptFile(Path, Output, wipeTimesToWrite);
            StringBuilder Expression = new StringBuilder($"The file '{Path}' was successfully encrypted. The ciphertext file name is '{Output}'");
            if (wipeTimesToWrite > 0) {
                Expression.Append($"\r\nThe plaintext file has also been erased from disk");
            }
            Console.WriteLine($"\r\n{Expression}\r\n");

            Result = new FileInfo(Output);
        }
    }
}
