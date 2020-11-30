using Microsoft.PowerShell.Commands;
using Org.X509Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace X509CryptoPOSH
{
    //public class ContextedAlias
    //{
    //    public X509Alias Alias;
    //    public X509Context Context;

    //    internal ContextedAlias(X509Alias Alias, X509Context Context)
    //    {
    //        this.Alias = Alias;
    //        this.Context = Context;
    //    }

    //    internal void CheckExists(bool mustExist = false, bool mustNotExist = false)
    //    {
    //        if (Alias.Exists())
    //        {
    //            if (mustNotExist)
    //            {
    //                throw new X509AliasAlreadyExistsException(Alias);
    //            }
    //        }
    //        else
    //        {
    //            if (mustExist)
    //            {
    //                throw new X509AliasNotFoundException(Alias);
    //            }
    //        }
    //    }
    //}
}
