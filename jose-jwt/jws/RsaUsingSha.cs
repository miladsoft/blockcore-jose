using System;
using System.Security.Cryptography;

namespace Blockcore.Jose
{
    public class RsaUsingSha : IJwsAlgorithm
    {
        private string hashMethod;

        public RsaUsingSha(string hashMethod)
        {
            this.hashMethod = hashMethod;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
            var privateKey = Ensure.Type<RSA>(key, "RsaUsingSha alg expects key to be of RSA type.");   
                         
            return privateKey.SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            var publicKey = Ensure.Type<RSA>(key, "RsaUsingSha alg expects key to be of RSA type.");   
                      
            return publicKey.VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        private HashAlgorithmName HashAlgorithm
        {
            get
            {
                if (hashMethod.Equals("SHA256"))
                    return HashAlgorithmName.SHA256;
                if (hashMethod.Equals("SHA384"))
                    return HashAlgorithmName.SHA384;
                if (hashMethod.Equals("SHA512"))
                    return HashAlgorithmName.SHA512;

                throw new ArgumentException("Unsupported hashing algorithm: '{0}'", hashMethod);
            }
        }
    }
}