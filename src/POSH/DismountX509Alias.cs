using System;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH {
    [Cmdlet(VerbsData.Dismount, nameof(X509Alias))]
    [OutputType(typeof(bool))]
    public class DismountX509Alias : Cmdlet {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = @"The X509Alias to dismount")]
        [Alias(nameof(X509Alias))]
        public X509Alias Alias;

        private bool Result = false;

        protected override void BeginProcessing() {
            base.BeginProcessing();
        }

        protected override void ProcessRecord() {
            base.ProcessRecord();
            DoWork();
            WriteObject(Result);
        }

        private void DoWork() {
            string name = Alias.Name;
            Alias.Dispose();
            Alias = null;
            Console.WriteLine($"{nameof(X509Alias)} '{name}' has been dismounted.");
            Result = true;
        }
    }
}
