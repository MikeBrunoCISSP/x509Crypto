using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.X509Crypto;

namespace X509CryptoPOSH
{
    public class RevealedSecret
    {
        public string Identifier { get; set; }
        public string Value { get; set; }

        public RevealedSecret(KeyValuePair<string,string> Secret)
        {
            Identifier = Secret.Key;
            Value = Secret.Value;
        }
    }
}
