using System;
using System.Management.Automation;
using Org.X509Crypto;

namespace X509CryptoPOSH {
    [Cmdlet(VerbsCommon.Remove, nameof(X509Alias))]
    [OutputType(typeof(bool))]
    public class RemoveAlias : Cmdlet {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = "The X509Alias to remove from the system")]
        [Alias(nameof(X509Alias))]
        public X509Alias Alias { get; set; }

        [Parameter(HelpMessage = "If enabled, no confirmation message will be displayed before X509Alias deletion.")]
        public SwitchParameter Quiet { get; set; } = false;

        [Parameter(HelpMessage = "If enabled, the X509Crypto encryption certificate associated with this X509Alias will also be deleted from the X509Context where it presently exists")]
        public SwitchParameter DeleteCert { get; set; } = false;

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
            var name = Alias.Name;
            var Context = Alias.Context;

            if (!Quiet && !Util.WarnConfirm($"The {nameof(X509Alias)} '{name}' will be removed from the '{Context.Name}' {nameof(X509Context)}. Any secrets contained in this {nameof(X509Alias)} will be unrecoverable.", Constants.Affirm)) {
                return;
            }

            Alias.Remove(DeleteCert);
            Alias.Dispose();
            Console.WriteLine($"Alias '{name}' has been removed from the '{Context.Name}' {nameof(X509Context)}");
            Result = true;
        }
    }
}
