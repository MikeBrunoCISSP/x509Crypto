using System;
using Org.X509Crypto;
using System.Management.Automation;
using System.IO;
using System.Text;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsSecurity.Protect, @"File")]
    [OutputType(typeof(FileInfo))]
    public class ProtectFile : Cmdlet
    {
        private string output = string.Empty;
        private bool outputSet = false;

        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = "The X509Alias to use for encryption")]
        [Alias(@"X509Alias")]
        public ContextedAlias Alias { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The path to the file to encrypt")]
        public string Path { get; set; }

        [Parameter(HelpMessage = "The path to which to write the encrypted file. If not specified, the name of the file indicated for \"\" will be appended with a \".ctx\" extension")]
        public string Output
        {
            get
            {
                return output;
            }
            set
            {
                output = value;
                outputSet = true;
            }
        }

        [Parameter(HelpMessage = "If $True, the plaintext file specified for \"Path\" will be wiped from disk. Default selection is $False.")]
        public bool Delete { get; set; } = false;

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
                Output = $"{Path}{FileExtensions.Ciphertext}";
            }
            Utils.CheckForExistingFile(Output, Overwrite, nameof(Overwrite));

            if (Delete)
            {
                if (Utils.WarnConfirm($"You have set the {nameof(Delete).InQuotes()} argument to $True. This will permanently delete the file {Path.InQuotes()} from disk."))
                {
                    wipeTimesToWrite = Constants.WipeRepititions;
                }
            }
            else
            {
                Delete = false;
            }


            Alias.Alias.EncryptFile(Path, Output, wipeTimesToWrite);
            StringBuilder Expression = new StringBuilder($"The file {Path.InQuotes()} was successfully encrypted. The ciphertext file name is {Output.InQuotes()}");
            if (Delete)
            {
                Expression.Append($"\r\nThe plaintext file has also been erased from disk");
            }
            Console.WriteLine($"\r\n{Expression}\r\n");

            Result = new FileInfo(Output);
        }
    }
}
