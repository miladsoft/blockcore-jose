using Blockcore.Networks;
using NBitcoin;

namespace Blockcore.Jose
{
   public class ProfileNetwork : Network
   {
      private static ProfileNetwork network;

      public static ProfileNetwork Instance
      {
         get
         {

            if (network == null)
            {
               network = new ProfileNetwork();
            }

            return network;
         }
      }

      public ProfileNetwork()
      {
         Name = "PROFILE";
         CoinTicker = "ID";

         Base58Prefixes = new byte[12][];
         Base58Prefixes[(int)Base58Type.PUBKEY_ADDRESS] = new byte[] { 55 };
         Base58Prefixes[(int)Base58Type.SCRIPT_ADDRESS] = new byte[] { 117 };
         Base58Prefixes[(int)Base58Type.SECRET_KEY] = new byte[] { 55 + 128 };
      }
   }
}
