using System;
using Org.X509Crypto;
using System.Management.Automation;

namespace X509CryptoPOSH
{

    [Cmdlet(VerbsData.Mount, nameof(X509Alias))]
    [OutputType(typeof(ContextedAlias))]
    public class MountX509Alias : Cmdlet
    {
        private string location = string.Empty;
        private bool locationSet = false;

        private bool contextSet = false;
        [Parameter(Mandatory = true, HelpMessage = "The name for the X509Alias to retrieve")]
        [Alias("N", "Alias")]
        public string Name { get; set; }

        [Parameter(HelpMessage = "The name of X509Context where the X509Alias exists. Acceptable values are \"user\" and \"system\"")]
        [Alias("Store")]
        public string Location
        {
            get
            {
                return location;
            }
            set
            {
                location = value;
                locationSet = true;
            }
        }

        [Parameter(ValueFromPipeline = true, HelpMessage = "The X509Context where the X509Alias exists. Not to be combined with the \"Location\" parameter")]
        [Alias("Context", "X509Context")]
        public X509Context Type
        {
            get
            {
                return context;
            }
            set
            {
                context = value;
                contextSet = true;
            }
        }

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
            if (!(locationSet ^ contextSet))
            {
                throw new InvalidParametersException(nameof(Location), nameof(Type));
            }

            if (locationSet)
            {
                context = X509Context.Select(Location, true);
            }

            X509Alias Alias = new X509Alias(Name, context);
            Result = new ContextedAlias(Alias, context);
            Result.CheckExists(mustExist: true);
            Console.WriteLine($"Alias {Name.InQuotes()} has been loaded from the {context.Name.InQuotes()} {nameof(X509Context)}");
        }
    }
}
