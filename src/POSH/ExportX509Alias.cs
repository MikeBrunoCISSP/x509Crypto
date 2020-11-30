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
    [Cmdlet(VerbsData.Export, nameof(X509Alias))]
    [OutputType(typeof(FileInfo))]
    public class ExportX509Alias : PSCmdlet
    {
        private string path = string.Empty;

        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = "The X509Alias to export")]
        [Alias(nameof(X509Alias))]
        public X509Alias Alias { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The path of the file to encrypt")]
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
                    if (!System.IO.Path.GetExtension(path).Matches(FileExtensions.X509Alias))
                    {
                        path = $"{path}{FileExtensions.X509Alias}";
                    }
                }
            }
        }

        [Parameter(HelpMessage = "If enabled and a file already exists in the indicated location for \"Path\" it will be overwritten. Default value is $False")]
        public SwitchParameter Overwrite { get; set; } = false;

        [Parameter(HelpMessage = "If enabled, and a file already exists in the indicated location for \"Path\" it will be overwritten. Only applicable if \"Overwrite\" = $True. Default value is $False ")]
        public SwitchParameter Quiet { get; set; } = false;

        private FileInfo Result;

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
            if (File.Exists(Path))
            {
                bool overWriteApproved = false;

                if (Overwrite)
                {
                    if (Quiet || Util.WarnConfirm($"A file already exists at the path {Path.InQuotes()}. Is it OK to overwrite it?", Constants.Affirm))
                    {
                        overWriteApproved = true;
                    }
                }

                if (!overWriteApproved)
                {
                    throw new X509CryptoException($"A file already exists at the path {Path.InQuotes()}. Set {nameof(Overwrite)} = {PoshSyntax.True} in order to enable overwriting.");
                }
            }

            Alias.Export(ref path, includeCert: true, Overwrite);
            Util.ConsoleMessage($"{nameof(X509Alias)} aliasName was successfully exported to file {Path.InQuotes()}");
            Result = new FileInfo(Path);
        }
    }
}
