using System;
using Org.X509Crypto;
using System.Management.Automation;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsCommon.Get, nameof(X509Context))]
    [OutputType(typeof(X509Context))]
    public class GetX509Context : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true,
                   HelpMessage = "The name of the X509Context in which to list existing X509Aliases. Acceptable values are \"user\" and \"system\"")]
        [Alias("Context", "X509Context", "StoreLocation", "CertStore", "Store")]
        public string Location { get; set; }

        [Parameter(HelpMessage = "Determines whether the X509Context should be open as writeable. Acceptable values are \"Read\" and \"Change\"")]
        public string Privilege { get; set; } = PrivilegeLevel.Read;

        private X509Context Result;

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
            Result = X509Context.Select(Location, Privilege.Matches(PrivilegeLevel.Change));
        }
    }
}
