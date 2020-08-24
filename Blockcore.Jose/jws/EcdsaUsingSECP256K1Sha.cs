using NBitcoin;
using NBitcoin.Crypto;
using System;
using System.Security.Cryptography;

namespace Blockcore.Jose
{
    public class EcdsaUsingSECP256K1Sha : IJwsAlgorithm
    {
        public EcdsaUsingSECP256K1Sha()
        {
            
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
            try
            {
                if (key is Key)
                {
                    var privateKey = (Key)key;

                    uint256 hash = Hashes.Hash256(securedInput);

                    var bytes = privateKey.SignCompact(hash);

                    return bytes;
                }

                throw new ArgumentException("EcdsaUsingSECP256K1Sha algorithm expects key to be of Key type.");
            }
            catch (CryptographicException e)
            {
                throw new JoseException("Unable to sign content.", e);
            }
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            try
            {
                if (key is PubKey)
                {
                    var publicKey = (PubKey)key;

                    uint256 hash = Hashes.Hash256(securedInput);

                    var valid = PubKey.RecoverCompact(hash, signature);

                    return publicKey.Hash == valid.Hash;
                }

                throw new ArgumentException("EcdsaUsingSECP256K1Sha algorithm expects key to be of either PubKey type.");
            }
            catch (CryptographicException e)
            {
                return false;
            }
        }
    }
}