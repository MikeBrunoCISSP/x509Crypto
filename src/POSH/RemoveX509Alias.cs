using System;
using Org.X509Crypto;
using System.Management.Automation;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsCommon.Remove, nameof(X509Alias))]
    [OutputType(typeof(bool))]
    public class RemoveAlias : Cmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "The name for the X509Alias to remove")]
        [Alias(nameof(ContextedAlias))]
        public ContextedAlias Alias { get; set; }

        [Parameter(HelpMessage = "If enabled, no confirmation message will be displayed before X509Alias deletion. Default selection is $False")]
        public SwitchParameter Quiet { get; set; } = false;

        private bool Result = false;

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
            var name = Alias.Alias.Name;
            var Context = Alias.Context;

            if (!Quiet && !Util.WarnConfirm($"The {nameof(X509Alias)} {name.InQuotes()} will be removed from the {Context.Name.InQuotes()} {nameof(X509Context)}. Any secrets contained in this {nameof(X509Alias)} will be unrecoverable.", Constants.Affirm))
            {
                return;
            }

            Alias.CheckExists(mustExist: true);
            Alias.Alias.Remove();
            Alias.Alias.Dispose();
            Console.WriteLine($"Alias {name.InQuotes()} has been removed from the {Context.Name.InQuotes()} {nameof(X509Context)}");
            Result = true;
        }
    }
}
