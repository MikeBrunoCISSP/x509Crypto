using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsSecurity.Unprotect, nameof(X509Alias))]
    [OutputType(typeof(RevealedSecret))]
    public class UnprotectX509Alias : Cmdlet
    {

        [Parameter(HelpMessage = "The X509Alias from which to list secrets")]
        [Alias(@"X509Alias")]
        public ContextedAlias Alias { get; set; }

        private List<RevealedSecret> Result = new List<RevealedSecret>();

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

            Dictionary<string, string> Dict = Alias.Alias.DumpSecrets(SecretDumpFormat.Dictionary, true);
            foreach(KeyValuePair<string, string> Pair in Dict)
            {
                Result.Add(new RevealedSecret(Pair));
            }
        }
    }
}
