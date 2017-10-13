using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using Com.AugustCellars.COSE;
using PeterO.Cbor;
using PeterO.Numbers;

namespace Com.AugustCellars.WebToken
{
    /// <summary>
    /// List of all known claims
    /// </summary>
    public enum ClaimId
    {
        Issuer = 1,
        Subject = 2,
        Audience = 3,
        ExpirationTime = 4,
        NotBefore = 5,
        IssuedAt = 6,
        CwtId = 7,
        Cnf = 9999,

    }

    /// <summary>
    /// Implementation of CBOR Web Token.
    /// 
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public class CWT
    {
        readonly CBORObject _claims = CBORObject.NewMap();

        private static readonly CBORObject _TagProfile = CBORObject.FromObject("profile");

        private static readonly Dictionary<string, CBORObject> _JwtMapping = new Dictionary<string, CBORObject>() {
            ["iss"] = CBORObject.FromObject(ClaimId.Issuer),
            ["sub"] = CBORObject.FromObject(ClaimId.Subject),
            ["aud"] = CBORObject.FromObject(ClaimId.Audience),
            ["exp"] = CBORObject.FromObject(ClaimId.ExpirationTime),
            ["nbf"] = CBORObject.FromObject(ClaimId.NotBefore),
            ["iat"] = CBORObject.FromObject(ClaimId.IssuedAt),
            ["cti"] = CBORObject.FromObject(ClaimId.CwtId)
        };

        /// <summary>
        /// Create a new CWT token
        /// </summary>
        public CWT()
        {

        }

        /// <summary>
        /// Create a CWT based on the passed in CBOR data.
        /// </summary>
        /// <param name="cbor">initial value</param>
        public CWT(CBORObject cbor)
        {
            if (cbor.Type != CBORType.Map) throw new CwtException("CWT must be a map");
            _claims = cbor;
        }

        /// <summary>
        /// Create a CWT based on the passed in byte.
        /// </summary>
        /// <param name="data">initial value</param>
        public CWT(byte[] data)
        {
            CBORObject cbor = CBORObject.DecodeFromBytes(data);
            if (cbor.Type != CBORType.Map) throw new CwtException("CWT must be a map");
            _claims = cbor;
        }

        /// <summary>
        /// Return the identifer of all claims in the token
        /// </summary>
        public ICollection<CBORObject> AllClaimKeys
        {
            get => _claims.Keys;
        }

        public String Audience
        {
            get => _claims[CBORObject.FromObject(ClaimId.Audience)].AsString();
            set => _claims.Add(CBORObject.FromObject(ClaimId.Audience), value);
        }

        public Confirmation Cnf
        {
            get => new Confirmation(_claims[CBORObject.FromObject(ClaimId.Cnf)]);
            set => _claims.Add((int) ClaimId.Cnf, value.AsCBOR);
        }

        public String Issuer {
            get => _claims[CBORObject.FromObject(ClaimId.Issuer)].AsString();
            set => _claims.Add(CBORObject.FromObject(ClaimId.Issuer), value);
        }

        public string Profile
        {
            get => _claims.ContainsKey(_TagProfile) ? _claims[_TagProfile].AsString() : null;
            set => _claims.Add(_TagProfile, value);
        }

        /// <summary>
        /// Does the token have a specific claim?
        /// </summary>
        /// <param name="claimId">id of the claim to check</param>
        /// <returns>if claim exists</returns>
        public bool HasClaim(ClaimId claimId)
        {
            return _claims.ContainsKey(CBORObject.FromObject(claimId));
        }

        /// <summary>
        /// Does the token have a specific claim?
        /// </summary>
        /// <param name="claimId">id of the claim to check</param>
        /// <returns>if claim exists</returns>
        public bool HasClaim(string claimId)
        {
            return HasClaim(CBORObject.FromObject(claimId));
        }

        /// <summary>
        /// Does the token have a specific claim?
        /// </summary>
        /// <param name="claimId">id of the claim to check</param>
        /// <returns>if claim exists</returns>
        public bool HasClaim(CBORObject claimId)
        {
            if (_claims.ContainsKey(claimId)) return true;
            if (claimId.Type == CBORType.TextString && _JwtMapping.ContainsKey(claimId.AsString())) {
                return _claims.ContainsKey(_JwtMapping[claimId.AsString()]);
            }
            return false;
        }

        /// <summary>
        /// Return a claim if it exists
        /// </summary>
        /// <param name="claimKey">claim to return</param>
        /// <returns>claim as a CBOR Object</returns>
        public CBORObject GetClaim(CBORObject claimKey)
        {
            if (!_claims.ContainsKey(claimKey) && claimKey.Type == CBORType.TextString) {
                if (_JwtMapping.ContainsKey(claimKey.AsString())) claimKey = _JwtMapping[claimKey.AsString()];
            }
            return _claims[claimKey];
        }

        /// <summary>
        /// Return a claim if it exists
        /// </summary>
        /// <param name="claimKey">claim to return</param>
        /// <returns>claim as a CBOR Object</returns>
        public CBORObject GetClaim(ClaimId claimKey)
        {
            return _claims[CBORObject.FromObject(claimKey)];
        }

        /// <summary>
        /// Return a claim if it exists
        /// </summary>
        /// <param name="claimKey">claim to return</param>
        /// <returns>claim as a CBOR Object</returns>
        public CBORObject GetClaim(string claimKey)
        {
            return GetClaim(CBORObject.FromObject(claimKey));
        }

        /// <summary>
        /// Access a claim in the token
        /// </summary>
        /// <param name="claimId">claim to access</param>
        /// <returns>value as a CBOR object</returns>
        public CBORObject this[CBORObject claimId]
        {
            get => GetClaim(claimId);
            set => SetClaim(claimId, value);
        }

        /// <summary>
        /// Access a claim in the token
        /// </summary>
        /// <param name="claimId">claim to access</param>
        /// <returns>value as a CBOR object</returns>
        public CBORObject this[ClaimId claimId]
        {
            get => GetClaim(claimId);
            set => SetClaim(claimId, value);
        }

        /// <summary>
        /// Set a claim in the token
        /// </summary>
        /// <param name="claim">Claim ID to set</param>
        /// <param name="value">value of the claim</param>
        public void SetClaim(ClaimId claim, string value)
        {
            SetClaim(claim, CBORObject.FromObject(value));
        }

        /// <summary>
        /// Set a claim in the token
        /// </summary>
        /// <param name="claim">Claim ID to set</param>
        /// <param name="value">value of the claim</param>
        public void SetClaim(string claim, string value)
        {
            SetClaim(CBORObject.FromObject(claim), CBORObject.FromObject(value));
        }

        /// <summary>
        /// Set a claim in the token
        /// </summary>
        /// <param name="claim">Claim ID to set</param>
        /// <param name="value">value of the claim</param>
        public void SetClaim(string claim, CBORObject value)
        {
            SetClaim(CBORObject.FromObject(claim), value);
        }

        /// <summary>
        /// Set a claim in the token
        /// </summary>
        /// <param name="claim">Claim ID to set</param>
        /// <param name="dt">value of the claim</param>
        public void SetClaim(ClaimId claim, DateTime dt)
        {
            double unixTime = (TimeZoneInfo.ConvertTime(dt, TimeZoneInfo.Utc) -
                               new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            CBORObject value = CBORObject.FromObject((long) unixTime);
            value = CBORObject.FromObjectAndTag(value, 1);
            SetClaim(claim, value);
        }

        /// <summary>
        /// Set a claim in the token
        /// </summary>
        /// <param name="claim">Claim ID to set</param>
        /// <param name="value">value of the claim</param>
        public void SetClaim(ClaimId claim, CBORObject value)
        {
            SetClaim(CBORObject.FromObject((Int32) claim), value);
        }

        /// <summary>
        /// Set a claim in the token
        /// </summary>
        /// <param name="claim">Claim ID to set</param>
        /// <param name="value">value of the claim</param>
        public void SetClaim(CBORObject claim, CBORObject value)
        {
            if (claim.Type == CBORType.Number) {
                switch ((ClaimId) claim.AsInt32()) {
                    case ClaimId.Issuer:
                    case ClaimId.Subject:
                    case ClaimId.Audience:
                        if (value.Type != CBORType.TextString) throw new CwtException("Claim value type is incorrect for the claim");
                        break;

                    case ClaimId.ExpirationTime:
                    case ClaimId.NotBefore:
                    case ClaimId.IssuedAt:
                        if (value.Type != CBORType.Number) throw new CwtException("Claim value type is incorrect for the claim");
                        if (value.GetAllTags().Count() != 0) throw new CwtException("Claim value type is incorrect for the claim");
                        break;

                    case ClaimId.CwtId:
                        if (value.Type != CBORType.ByteString) throw new CwtException("Claim value type is incorrect for the claim");
                        break;

                    case ClaimId.Cnf:
                        if (value.Type != CBORType.Map) throw new CwtException("Claim value type is incorect for the claim");
                        break;

                    default:
                        //  We don't know how to check this
                        break;
                }
            }
            else if (claim.Type == CBORType.TextString) {
                if (_JwtMapping.ContainsKey(claim.AsString())) {
                    SetClaim(_JwtMapping[claim.AsString()], value);
                    return;
                }
                //  We don't have any checks at this point to enforce.
            }
            else {
                throw new CwtException("Claim name must be integer or string");
            }

            _claims[claim] = value;
        }


        #region EncodingToken

        /// <summary>
        /// Get/Set the key for encrypting the token
        /// </summary>
        public OneKey EncryptionKey { get; set; }

        /// <summary>
        /// Get/Set the key used for signing the token
        /// </summary>
        public OneKey SigningKey { get; set; }

        /// <summary>
        /// Get/Set the key used for MACing the token
        /// </summary>
        public OneKey MacKey { get; set; }

        /// <summary>
        /// Create a CBOR encoding of the token
        /// </summary>
        /// <returns></returns>
        public CBORObject EncodeToCBOR()
        {
            if (EncryptionKey == null && SigningKey == null && MacKey == null) throw new CwtException("Must either encrypt, Sign or MAC a CWT object");

            CBORObject msg = _claims;

            if (SigningKey != null) {
                Sign1Message sigMsg = new Sign1Message();

                sigMsg.AddAttribute(HeaderKeys.Algorithm, SigningKey[CoseKeyKeys.Algorithm], Attributes.PROTECTED);
                if (SigningKey.ContainsName(CoseKeyKeys.KeyIdentifier)) {
                    sigMsg.AddAttribute(HeaderKeys.KeyId, SigningKey[CoseKeyKeys.KeyIdentifier], Attributes.UNPROTECTED);
                }
                sigMsg.SetContent(msg.EncodeToBytes());

                sigMsg.Sign(SigningKey);

                msg = sigMsg.EncodeToCBORObject();
            }

            if (MacKey != null) {
                MAC0Message macMsg = new MAC0Message();

                macMsg.AddAttribute(HeaderKeys.Algorithm, MacKey[CoseKeyKeys.Algorithm], Attributes.PROTECTED);
                macMsg.AddAttribute(HeaderKeys.KeyId, MacKey[CoseKeyKeys.KeyIdentifier], Attributes.UNPROTECTED);
                macMsg.SetContent(msg.EncodeToBytes());

                macMsg.Compute(MacKey[CoseKeyParameterKeys.Octet_k].GetByteString());

                msg = macMsg.EncodeToCBORObject();
            }

            if (EncryptionKey != null) {
                Encrypt0Message enc = new Encrypt0Message();

                enc.AddAttribute(HeaderKeys.Algorithm, EncryptionKey[CoseKeyKeys.Algorithm], Attributes.PROTECTED);
                if (EncryptionKey.ContainsName(HeaderKeys.KeyId)) {
                    enc.AddAttribute(HeaderKeys.KeyId, EncryptionKey[CoseKeyKeys.KeyIdentifier], Attributes.UNPROTECTED);
                }
                enc.SetContent(msg.EncodeToBytes());

                enc.Encrypt(EncryptionKey[CoseKeyParameterKeys.Octet_k].GetByteString());

                msg = enc.EncodeToCBORObject();
            }

            msg = CBORObject.FromObjectAndTag(msg, 61);
            return msg;
        }

        /// <summary>
        /// Convert the token to a string of bytes
        /// </summary>
        /// <returns>encoded token</returns>
        public byte[] EncodeToBytes()
        {
            return EncodeToCBOR().EncodeToBytes();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="encodedToken"></param>
        /// <param name="myDecryptKeySet"></param>
        /// <param name="asSignKeySet"></param>
        /// <returns></returns>
        public static CWT Decode(byte[] encodedToken, KeySet myDecryptKeySet, KeySet asSignKeySet)
        {
            return Decode(encodedToken, (data, coseObject) => KeysFromKeySet(myDecryptKeySet, coseObject),
                (data, coseObject) => KeysFromKeySet(asSignKeySet, coseObject));
        }

        public delegate IEnumerable<OneKey> FindKeys(Object appData, Attributes coseObject);

        private static IEnumerable<OneKey> KeysFromKeySet(Object appData, Attributes coseObject)
        {
            CBORObject kid = coseObject.FindAttribute(HeaderKeys.KeyId);
            CBORObject alg = coseObject.FindAttribute(HeaderKeys.Algorithm);
            KeySet keySet = (KeySet) appData;

            foreach (OneKey key in keySet) {
                if (kid == null) {
                    if (key.ContainsName(HeaderKeys.KeyId)) continue;
                }
                else if (!key.HasKid(kid.GetByteString())) continue;

                yield return key;
            }
        }


        public static CWT Decode(byte[] encodedToken, FindKeys getKeyFunction, FindKeys getSignKey)
        {
            CBORObject cbor = CBORObject.DecodeFromBytes(encodedToken);
            OneKey encryptionKey = null;
            OneKey signKey = null;
            OneKey macKey = null;

            if (cbor.IsTagged && cbor.MostOuterTag.ToInt32Unchecked() == 61) {
                cbor = cbor.UntagOne();
            }

            do {
                if (cbor.GetAllTags().Length != 1) throw new CwtException("Malformed CWT structure");

                Message msg = Message.DecodeFromCBOR(cbor);

                if (msg is Encrypt0Message) {
                    Encrypt0Message enc0 = (Encrypt0Message) msg;

                    if (encryptionKey != null) throw new CwtException("Multiple encryption nesting is not handled");

                    IEnumerable<OneKey> keys = getKeyFunction(null, enc0);

                    encodedToken = null;

                    foreach (OneKey testKey in keys) {
                        try {
                            encodedToken = enc0.Decrypt(testKey[CoseKeyParameterKeys.Octet_k].GetByteString());
                            encryptionKey = testKey;
                            break;
                        }
                        catch {
                            ;
                        }
                    }

                    if (encryptionKey == null) {
                        throw new CwtException("Failed to find a key to decrypt with");
                    }
                }
                else if (msg is MAC0Message) {
                    MAC0Message enc0 = (MAC0Message)msg;

                    if (macKey != null) throw new CwtException("Multiple MAC nesting is not handled");

                    IEnumerable<OneKey> keys = getKeyFunction(null, enc0);

                    encodedToken = null;

                    foreach (OneKey testKey in keys) {
                        try {
                            if (enc0.Validate(testKey[CoseKeyParameterKeys.Octet_k].GetByteString())) {
                                macKey = testKey;
                                encodedToken = enc0.GetContent();
                                break;
                            }
                        }
                        catch {
                            ;
                        }
                    }

                    if (macKey == null) {
                        throw new CwtException("Failed to find a key to verify the MAC with");
                    }
                }

                else if (msg is Sign1Message) {
                    Sign1Message sign1 = (Sign1Message) msg;
                    if (signKey != null) throw new CwtException("Multiple signature nesting is not handled.");
                    if (getKeyFunction == null) throw new CwtException("Failed to find a key to validate the signature with.");
                    IEnumerable<OneKey> keys = getSignKey(null, sign1);

                    encodedToken = null;

                    foreach (OneKey testkey in keys) {
                        try {
                            if (sign1.Validate(testkey)) {
                                encodedToken = sign1.GetContent();
                                signKey = testkey;
                                break;
                            }
                        }
                        catch { 
                        ;
                        }
                    }

                    if (signKey == null) throw new CwtException("Failed to find a key to validate the signature with.");
                }

                cbor = CBORObject.DecodeFromBytes(encodedToken);

            } while (cbor.IsTagged);

            CWT cwt = new CWT(cbor) {
                EncryptionKey = encryptionKey,
                MacKey = macKey,
                SigningKey =  signKey
            };

            return cwt;
        }


        #endregion
    }
}
