using System;
using Org.X509Crypto;
using System.Management.Automation;
using System.IO;
using System.Text;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsData.Update, @"X509CryptoFileEncryption")]
    [OutputType(typeof(FileInfo))]
    public class UpdateX509CryptoFileEncryption : PSCmdlet
    {
        private string path = string.Empty;

        [Parameter(Mandatory = true, HelpMessage = "The X509Alias that was previously used to encrypt the file")]
        [Alias(@"OldAlias", @"OldX509Alias", @"CurrentX509Alias")]
        public X509Alias CurrentAlias { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The X509Alias that will re-encrypt the file")]
        [Alias(@"NewAlias", @"NewX509Alias", @"TargetX509Alias")]
        public X509Alias TargetAlias { get; set; }

        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = "The path of the encrytped file which needs to be re-encrypted using a different X509Alias")]
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

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        private FileInfo Result;

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            DoWork();
            WriteObject(Result);
        }

        private void DoWork()
        {
            TargetAlias.ReEncryptFile(Path, CurrentAlias);
            //X509Utils.ReEncryptFile(CurrentAlias, TargetAlias, Path);
            Console.WriteLine($"\r\nThe file {Path} was successfully re-encrypted using the X509Crypto alias {TargetAlias.Name} located in the {TargetAlias.Context.Name.InQuotes()} {nameof(X509Context)}");
            Result = new FileInfo(Path);
        }
    }
}
