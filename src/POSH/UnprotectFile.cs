using System;
using Org.X509Crypto;
using System.Management.Automation;
using System.IO;
using System.Text;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsSecurity.Unprotect, @"File")]
    [OutputType(typeof(FileInfo))]
    public class UnprotectFile : PSCmdlet
    {
        private string path = string.Empty;
        private string output = string.Empty;
        private bool outputSet = false;

        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = "The X509Alias that was used to encrypt the file")]
        [Alias(@"X509Alias")]
        public ContextedAlias Alias { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The path to the file to decrypt")]
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
                    path = new FileInfo(System.IO.Path.Combine(SessionState.Path.CurrentLocation.Path, value)).FullName;
                }
            }
        }

        [Parameter(HelpMessage = "The path to which to write the decrypted file. If not specified, the original plaintext file name will be restored, or will be appended with a \".ptx\" file extension")]
        public string Output
        {
            get
            {
                return output;
            }
            set
            {
                if (System.IO.Path.IsPathRooted(value))
                {
                    output = value;
                }
                else
                {
                    output = new FileInfo(System.IO.Path.Combine(SessionState.Path.CurrentLocation.Path, value)).FullName;
                }
                outputSet = true;
            }
        }

        [Parameter(HelpMessage = "If $True, the ciphertext file specified for \"Path\" will be wiped from disk. Default selection is $False.")]
        public bool Delete { get; set; } = false;

        [Parameter(HelpMessage = "If $False, no warning will be displayed before the ciphertext file specified for \"Path\" is wiped from disk. Not appliable if \"-Delete\" is $False")]
        public bool Confirm { get; set; } = true;

        [Parameter(HelpMessage = "If $True, should a file already exist under the same path as specified/inferred for \"Output\", it will be replaced. Default selection is $False.")]
        public bool Overwrite { get; set; } = false;

        private FileInfo Result = null;

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
            int wipeTimesToWrite = 0;
            if (!File.Exists(Path))
            {
                throw new FileNotFoundException($"The file path indicated for the {nameof(Path).InQuotes()} parameter ({Path}) does not exist");
            }

            if (!outputSet)
            {
                Output = Util.GetPlaintextFilename(Path);
            }
            Util.CheckForExistingFile(Output, Overwrite, nameof(Overwrite), PoshSyntax.True);

            if (Delete)
            {
                if (!Confirm || Util.WarnConfirm($"You have set the {nameof(Delete).InQuotes()} argument to $True. This will permanently delete the file {Path.InQuotes()} from disk.", Constants.Affirm))
                {
                    wipeTimesToWrite = Constants.WipeRepititions;
                }
            }
            else
            {
                Delete = false;
            }


            Alias.Alias.DecryptFile(Path, Output, wipeTimesToWrite);
            StringBuilder Expression = new StringBuilder($"The file {Path.InQuotes()} was successfully decrypted. The recovered file name is {Output.InQuotes()}");
            if (Delete)
            {
                Expression.Append($"\r\nThe ciphertext file has also been erased from disk");
            }
            Console.WriteLine($"\r\n{Expression}\r\n");

            Result = new FileInfo(Output);
        }
    }
}
