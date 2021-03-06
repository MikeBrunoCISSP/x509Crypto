﻿using Org.X509Crypto;
using System;
using System.Management.Automation;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsData.Update, nameof(X509Alias))]
    [OutputType(typeof(X509Alias))]
    public class UpdateX509Alias : Cmdlet
    {
        private string context = string.Empty;
        private bool contextSet = false;
        private string thumbprint = string.Empty;

        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = "The source X509Alias from which to move all protected secrets")]
        [Alias(@"X509Alias")]
        public X509Alias Alias { get; set; }

        [Parameter(HelpMessage = "The X509Context where the new encryption certificate exists. If not specified, the X509Context of the entry for \"Alias\" will be used. Acceptable entries are \"user\" and \"system\".")]
        [Alias("Context", "X509Context", "StoreLocation", "CertStore", "CertStoreLocation", "Store")]
        public string Location
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

        [Parameter(Mandatory = true, HelpMessage = "The thumbprint of the new encryption certificate")]
        public string Thumbprint
        {
            get
            {
                return thumbprint;
            }
            set
            {
                if (!Util.IsCertThumbprint(value))
                {
                    throw new FormatException($"{value.InQuotes()}: Not a valid certificate thumbprint");
                }
                thumbprint = value;
            }
        }

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            DoWork();
            WriteObject(Alias);
        }

        private void DoWork()
        {
            X509Context OldContext,
                        NewContext;

            OldContext = Alias.Context;
            if (contextSet)
            {
                NewContext = X509Context.Select(Location, false);
            }
            else
            {
                NewContext = Alias.Context;
            }

            if (!X509CryptoAgent.CertificateExists(Thumbprint, NewContext))
            {
                throw new X509CryptoCertificateNotFoundException(Thumbprint, NewContext);
            }
            Alias.ReEncrypt(Thumbprint, NewContext);
            Alias.Commit();
            Console.WriteLine($"{nameof(X509Alias)} {Alias.Name} successfully updated. Now using encryption certificate with thumbprint {Thumbprint} from the {NewContext.Name} {nameof(X509Context)}");
        }
    }
}
