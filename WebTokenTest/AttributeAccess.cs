using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;
using Com.AugustCellars.WebToken;
using PeterO.Cbor;


namespace WebTokenTest
{
    [TestFixture]
    public class AttributeAccess
    {
        [Test]
        public void Test_Audience()
        {
            CWT cwt = new CWT();

            Assert.AreEqual(false, cwt.HasClaim(ClaimId.Audience));
            Assert.AreEqual(false, cwt.HasClaim("aud"));
            cwt.Audience = "Audience1";
            Assert.AreEqual(true, cwt.HasClaim(ClaimId.Audience));
            Assert.AreEqual(true, cwt.HasClaim("aud"));

            Assert.AreEqual("Audience1", cwt.GetClaim(ClaimId.Audience).AsString());
            Assert.AreEqual("Audience1", cwt.GetClaim("aud").AsString());
            Assert.AreEqual("Audience1", cwt[ClaimId.Audience].AsString());

            CwtException e = Assert.Throws<CwtException>(() =>
                cwt.SetClaim(ClaimId.Audience, CBORObject.FromObject(1)));

            cwt.SetClaim("aud", "TestValue");
            Assert.AreEqual(cwt.Audience, "TestValue");
        }

        [Test]
        public void Test_Issuer()
        {
            CWT cwt = new CWT();

            Assert.AreEqual(false, cwt.HasClaim(ClaimId.Issuer));
            Assert.AreEqual(false, cwt.HasClaim("iss"));
            cwt.Issuer = "Audience1";
            Assert.AreEqual(true, cwt.HasClaim(ClaimId.Issuer));
            Assert.AreEqual(true, cwt.HasClaim("iss"));

            Assert.AreEqual("Audience1", cwt.GetClaim(ClaimId.Issuer).AsString());
            Assert.AreEqual("Audience1", cwt.GetClaim("iss").AsString());
            Assert.AreEqual("Audience1", cwt[ClaimId.Issuer].AsString());

            CwtException e = Assert.Throws<CwtException>(() =>
                cwt.SetClaim(ClaimId.Issuer, CBORObject.FromObject(1)));

            cwt.SetClaim("iss", "TestValue");
            Assert.AreEqual(cwt.Issuer, "TestValue");

        }
    }
}
