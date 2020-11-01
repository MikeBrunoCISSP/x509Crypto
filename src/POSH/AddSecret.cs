using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.X509Crypto;
using System.Management.Automation;

namespace X509CryptoPOSH
{
    [Cmdlet(VerbsCommon.Add, @"Secret")]
    public class AddSecret : Cmdlet
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true, HelpMessage = "The X509Alias which points to the encryption certificate")]
        public string Alias { get; set; } = string.Empty;

        [Parameter(Mandatory = true, HelpMessage = "The X509Context in which the encryption certificate exists. Acceptable values are \"user\" and \"system\"")]
        [Alias("X509Context", "Store")]
        public string Context { get; set; } = string.Empty;

        [Parameter(Mandatory = true, HelpMessage = "The identifier for the secret to be stored in the X509Alias")]
        [Alias("Identifier")]
        public string Name { get; set; } = string.Empty;

        [Parameter(Mandatory = true, HelpMessage = "The text secret to be protected within the X509Alias")]
        [Alias("Ciphertext")]
        public string Secret { get; set; } = string.Empty;
    }
}
