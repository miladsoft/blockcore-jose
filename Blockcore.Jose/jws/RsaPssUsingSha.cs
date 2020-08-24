using System;
using System.Security.Cryptography;
using Security.Cryptography;

namespace Blockcore.Jose
{
   public class RsaPssUsingSha : IJwsAlgorithm
   {
      private int saltSize;

      public RsaPssUsingSha(int saltSize)
      {
         this.saltSize = saltSize;
      }

      public byte[] Sign(byte[] securedInput, object key)
      {
         if (key is CngKey)
         {
            var privateKey = (CngKey)key;

            try
            {
               return RsaPss.Sign(securedInput, privateKey, Hash, saltSize);
            }
            catch (CryptographicException e)
            {
               throw new JoseException("Unable to sign content.", e);
            }
         }

         if (key is RSACryptoServiceProvider)
         {
            //This is for backward compatibility only with 2.x 
            //To be removed in 3.x 
            var privateKey = RsaKey.New(((RSACryptoServiceProvider)key).ExportParameters(true));

            try
            {
               return RsaPss.Sign(securedInput, privateKey, Hash, saltSize);
            }
            catch (CryptographicException e)
            {
               throw new JoseException("Unable to sign content.", e);
            }
         }

         if (key is RSA)
         {
            var privateKey = (RSA)key;
            return privateKey.SignData(securedInput, HashAlgorithm, RSASignaturePadding.Pss);
         }

         throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of either CngKey or RSA types.");
      }

      public bool Verify(byte[] signature, byte[] securedInput, object key)
      {
         if (key is CngKey)
         {
            var publicKey = (CngKey)key;

            try
            {
               return RsaPss.Verify(securedInput, signature, publicKey, Hash, saltSize);
            }
            catch (CryptographicException e)
            {
               return false;
            }
         }

         if (key is RSACryptoServiceProvider)
         {
            //This is for backward compatibility only with 2.x 
            //To be removed in 3.x 
            var publicKey = RsaKey.New(((RSACryptoServiceProvider)key).ExportParameters(false));

            try
            {
               return RsaPss.Verify(securedInput, signature, publicKey, Hash, saltSize);
            }
            catch (CryptographicException e)
            {
               return false;
            }
         }

         if (key is RSA)
         {
            var publicKey = (RSA)key;

            return publicKey.VerifyData(securedInput, signature, HashAlgorithm, RSASignaturePadding.Pss);
         }

         throw new ArgumentException("RsaUsingSha with PSS padding alg expects key to be of either CngKey or RSA types.");
      }

      private HashAlgorithmName HashAlgorithm
      {
         get
         {
            if (saltSize == 32)
               return HashAlgorithmName.SHA256;
            if (saltSize == 48)
               return HashAlgorithmName.SHA384;
            if (saltSize == 64)
               return HashAlgorithmName.SHA512;

            throw new ArgumentException(string.Format("Unsupported salt size: '{0} bytes'", saltSize));
         }
      }

      private CngAlgorithm Hash
      {
         get
         {
            if (saltSize == 32)
               return CngAlgorithm.Sha256;
            if (saltSize == 48)
               return CngAlgorithm.Sha384;
            if (saltSize == 64)
               return CngAlgorithm.Sha512;

            throw new ArgumentException(string.Format("Unsupported salt size: '{0} bytes'", saltSize));
         }
      }

   }
}
