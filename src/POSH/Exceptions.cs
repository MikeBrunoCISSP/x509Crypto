using Org.X509Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace X509CryptoPOSH
{
    public class InvalidParametersException : Exception
    {
        public InvalidParametersException(string paramName1, string paramName2)
            : base($"Either the {paramName1.InQuotes()} or the {paramName2.InQuotes()} must be specified, but not both")
        { }
    }
}
