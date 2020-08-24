using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Blockcore.Jose
{
    public class RsaOaep256KeyManagement : IKeyManagement
    {
        public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            var cek = Arrays.Random(cekSizeBits);

            if (key is CngKey)
            {
                var publicKey = (CngKey) key;

                return new[] {cek, RsaOaep.Encrypt(cek, publicKey, CngAlgorithm.Sha256)};
            }

            if (key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var publicKey = RsaKey.New(((RSACryptoServiceProvider) key).ExportParameters(false));

                return new[] {cek, RsaOaep.Encrypt(cek, publicKey, CngAlgorithm.Sha256)};
            }

            if (key is RSA)
            {
	            var publicKey = (RSA) key;

                return new[] { cek, publicKey.Encrypt(cek, RSAEncryptionPadding.OaepSHA256) };
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of either CngKey or RSA types.");

        }

        public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            if (key is CngKey)
            {
                var privateKey = (CngKey) key;

	            return RsaOaep.Decrypt(encryptedCek, privateKey, CngAlgorithm.Sha256);
            }

            if (key is RSACryptoServiceProvider)
            {
                //This is for backward compatibility only with 2.x 
                //To be removed in 3.x 
                var privateKey = RsaKey.New(((RSACryptoServiceProvider) key).ExportParameters(true));

                return RsaOaep.Decrypt(encryptedCek, privateKey, CngAlgorithm.Sha256);
            }

            if (key is RSA)
            {
                var privateKey = (RSA) key;

                return privateKey.Decrypt(encryptedCek, RSAEncryptionPadding.OaepSHA256);				
            }

            throw new ArgumentException("RsaKeyManagement algorithm expects key to be of either CngKey or RSA types.");

        }
    }
}