using System;
using Org.X509Crypto;
using System.Management.Automation;

namespace X509CryptoPOSH
{

    [Cmdlet(VerbsData.Mount, nameof(X509Alias))]
    [OutputType(typeof(ContextedAlias))]
    public class MountX509Alias : Cmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "The name for the X509Alias to retrieve")]
        [Alias("N", "Alias")]
        public string Name { get; set; }

        [Parameter(Mandatory = true, HelpMessage = "The X509Context where the X509Alias exists. Acceptable values are \"user\" and \"system\"")]
        [Alias("X509Context", "Store")]
        public string Context { get; set; }

        private X509Context context;
        private ContextedAlias Result;

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
            context = X509Context.Select(Context, true);
            X509Alias Alias = new X509Alias(Name, context);
            Result = new ContextedAlias(Alias, context);
            Result.CheckExists(mustExist: true);
            Console.WriteLine($"Alias {Name.InQuotes()} has been loaded from the {context.Name.InQuotes()} {nameof(X509Context)}");
        }
    }
}
