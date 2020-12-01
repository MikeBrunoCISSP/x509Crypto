using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.X509Crypto;

namespace Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            var OldAlias = new X509Alias(@"exporttest", X509Context.UserFull);
            var NewAlias = new X509Alias(@"updateSample", X509Context.UserFull);

            OldAlias.EncryptFile(@"P:\_temp\test.docx", @"P:\_temp\test.docx.ctx");
            NewAlias.ReEncryptFile(@"P:\_temp\test.docx.ctx", OldAlias);
        }
    }
}
