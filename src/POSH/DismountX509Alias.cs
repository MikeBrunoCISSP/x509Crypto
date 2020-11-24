using System;
using Org.X509Crypto;
using System.Management.Automation;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsData.Dismount, nameof(X509Alias))]
    [OutputType(typeof(ContextedAlias))]
    public class DismountX509Alias : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = @"The X509Context to dismount")]
        [Alias("Alias", @"X509Alias")]
        public ContextedAlias Name;

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            DoWork();
            WriteObject(Name);
        }

        private void DoWork()
        {
            string name = Name.Alias.Name;
            Name.Alias.Dispose();
            Name = null;
            Console.WriteLine($"{nameof(X509Alias)} {name.InQuotes()} has been dismounted.");
        }
    }
}
