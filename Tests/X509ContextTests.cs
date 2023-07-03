using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.X509Crypto;

namespace Tests {
    [TestClass]
    public class X509ContextTests {
        [TestMethod]
        public void TestEquals() {
            var userReadOnly = X509Context.UserReadOnly;
            var other = X509Context.UserReadOnly;
            var userFull = X509Context.UserFull;
            Assert.AreEqual(userReadOnly, other);
            Assert.AreNotEqual(userReadOnly, userFull);
        }
    }
}
