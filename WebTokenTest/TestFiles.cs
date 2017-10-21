using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using PeterO.Cbor;
using System.IO;
using Com.AugustCellars.WebToken;
using Com.AugustCellars.COSE;

namespace WebTokenTest
{
    [TestFixture]
    public class TestFiles
    {
        [Test]
        public void RunFiles()
        {
            DirectoryInfo di = new DirectoryInfo("./Tests");
            ProcessDirectory(di);

        }

        void ProcessDirectory(DirectoryInfo dir)
        {
            foreach (DirectoryInfo child in dir.EnumerateDirectories()) {
                ProcessDirectory(child);
            }

            foreach (FileInfo testCase in dir.EnumerateFiles()) {
                ProcessFile(testCase);
            }
        }

        void ProcessFile(FileInfo testCase)
        {
            if (testCase.Extension != ".json") return;
            if (testCase.Name[0] == '.') return;

            Debug.Print($"Working on file {testCase}");
            Console.WriteLine("Working on file '" + testCase + "'");

            string inputText = testCase.OpenText().ReadToEnd();
            CBORObject test = CBORObject.FromJSONString(inputText);
            KeySet decodeKeys = new KeySet();
            KeySet signKeys = new KeySet();

            CBORObject input = test["input"];

            CWT cwt = new CWT();

            if (input.ContainsKey("encrypted")) {
                OneKey key = LoadKey(input["encrypted"]["key"]);
                cwt.EncryptionKey = key;
                decodeKeys.AddKey(key);
            }

            if (input.ContainsKey("mac0")) {
                OneKey key = LoadKey(input["mac0"]["key"]);
                cwt.MacKey = key;
                decodeKeys.AddKey(key);
            }

            if (input.ContainsKey("sign0")) {
                OneKey key = LoadKey(input["sign0"]["key"]);
                cwt.SigningKey = key;
                signKeys.AddKey(key.PublicKey());
            }

            CWT cwt2 = CWT.Decode(FromHex(test["output"]["cbor"].AsString()), decodeKeys, signKeys);



            CBORObject token = input["token"];
            foreach (CBORObject key in token.Keys) {
                CBORObject value = token[key];
                CBORObject key2 = key;
                if (key.AsString().EndsWith("_hex")) {
                    value = CBORObject.FromObject(FromHex(value.AsString()));
                    key2 = CBORObject.FromObject(key.AsString().Substring(0, key.AsString().Length - 4));
                }

                cwt.SetClaim(key2, value);

                Assert.True(cwt2.HasClaim(key2), $"Missing Claim {key2}");
                Assert.AreEqual(value, cwt.GetClaim(key2));
            }

            byte[] foo = cwt.EncodeToBytes();

            cwt2 = CWT.Decode(foo, decodeKeys, signKeys);
            foreach (CBORObject key in token.Keys) {
                CBORObject value = token[key];
                CBORObject key2 = key;
                if (key.AsString().EndsWith("_hex")) {
                    value = CBORObject.FromObject(FromHex(value.AsString()));
                    key2 = CBORObject.FromObject(key.AsString().Substring(0, key.AsString().Length - 4));
                }

                Assert.True(cwt2.HasClaim(key2));
                Assert.AreEqual(value, cwt.GetClaim(key2));
            }
        }

        OneKey LoadKey(CBORObject obj)
        {
            OneKey newKey = new OneKey();
            CBORObject kty;

            switch (obj["kty"].AsString()) {
                        case "oct":
                            kty = GeneralValues.KeyType_Octet;
                            break;

                        case "EC":
                            kty = GeneralValues.KeyType_EC;
                            break;

                        default:
                            throw new Exception("Unknown key type " + obj["cty"].AsString());
                    }

            foreach (CBORObject key in obj.Keys) {
                CBORObject value = obj[key];
                CBORObject key2 = key;

                if (key.AsString().EndsWith("_hex")) {
                    value = CBORObject.FromObject(FromHex(value.AsString()));
                    key2 = CBORObject.FromObject(key.AsString().Substring(0, key.AsString().Length - 4));
                }

                key2 = MapKey(key2);
                if (key2.Equals(CoseKeyKeys.KeyType)) {
                    value = kty;
                }
                else if (key2.Equals(CoseKeyKeys.KeyIdentifier)) {
                    value = CBORObject.FromObject(Encoding.UTF8.GetBytes(value.AsString()));
                }
                else if (key2.Equals(CoseKeyKeys.Algorithm)) value = MapAlgorithm(value.AsString());
                else if (kty.Equals(GeneralValues.KeyType_EC) && key2.Equals(CoseKeyParameterKeys.EC_Curve)) {
                    switch (value.AsString()) {
                        case "P-256":
                            value = GeneralValues.P256;
                            break;

                        default:
                            throw new Exception("Unknown curve " + value.AsString());
                    }
                }

                newKey.Add(key2, value);
            }

            return newKey;
        }

     

        byte[] FromHex(string hex)
        {
                int numberChars = hex.Length;
                byte[] bytes = new byte[numberChars / 2];
                for (int i = 0; i < numberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
        }

        private CBORObject MapAlgorithm(string algName)
        {
            switch (algName) {
                case "AES-CCM-16-128/64": return AlgorithmValues.AES_CCM_16_64_128;
                case "ES256": return AlgorithmValues.ECDSA_256;
                case "HS256/64": return AlgorithmValues.HMAC_SHA_256_64;
                default: throw new Exception("Unknown algorithm name " + algName);
            }
        }

        private CBORObject MapKey(CBORObject key)
        {
            
            switch (key.AsString())
            {
                case "kty": return CoseKeyKeys.KeyType;
                case "kid": return CoseKeyKeys.KeyIdentifier;
                case "k": return CoseKeyParameterKeys.Octet_k;
                //               case "use": return CoseKeyKeys.Key_Operations;
                case "crv": return CoseKeyParameterKeys.EC_Curve;
                case "d": return CoseKeyParameterKeys.EC_D;
                case "y": return CoseKeyParameterKeys.EC_Y;
                case "x": return CoseKeyParameterKeys.EC_X;

                case "alg": return CoseKeyKeys.Algorithm;
                default:
                    throw new Exception("MapKey - unknown key " + key.AsString());

                case "use": return key;
            }
        }
    }
}
