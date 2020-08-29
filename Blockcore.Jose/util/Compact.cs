using System;
using System.IO;
using System.Text;
using System.Threading;

namespace Blockcore.Jose
{
   public class Compact
   {
      public static string Serialize(params byte[][] parts)
      {
         var builder = new StringBuilder();

         foreach (byte[] part in parts)
         {
            builder.Append(Base64Url.Encode(part)).Append(".");
         }

         builder.Remove(builder.Length - 1, 1);

         return builder.ToString();
      }

      public static string Serialize(byte[] header, string payload, params byte[][] other)
      {
         StringBuilder builder = new StringBuilder()
             .Append(Base64Url.Encode(header))
             .Append(".")
             .Append(payload)
             .Append(".");

         foreach (byte[] part in other)
         {
            builder.Append(Base64Url.Encode(part)).Append(".");
         }

         builder.Remove(builder.Length - 1, 1);

         return builder.ToString();
      }

      public static byte[][] Parse(string token)
      {
         if (token == null)
            throw new ArgumentNullException(nameof(token));

         string[] parts = token.Split('.');

         byte[][] result = new byte[parts.Length][];

         for (int i = 0; i < parts.Length; i++)
         {
            result[i] = Base64Url.Decode(parts[i]);
         }

         return result;
      }

      public static Iterator Iterate(string token)
      {
         if (token == null)
            throw new ArgumentNullException(nameof(token));

         return new Iterator(token.Split('.'));
      }

      public class Iterator
      {
         private readonly string[] parts;
         private int current;

         public Iterator(string[] parts)
         {
            this.parts = parts;
            current = 0;
         }

         public int Count
         {
            get { return parts.Length; }
         }

         public byte[] Next(bool decode = true)
         {
            if (current < parts.Length)
            {
               string part = parts[current++];

               return decode ? Base64Url.Decode(part) : Encoding.UTF8.GetBytes(part);
            }

            return null;
         }
      }
   }
}
