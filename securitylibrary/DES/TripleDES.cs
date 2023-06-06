using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.DES;
namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            string res = des.Decrypt(cipherText, key[0]);
            res = des.Encrypt(res, key[1]);
            res = des.Decrypt(res, key[1]);
            return res;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES des = new DES();
            string res = des.Encrypt(plainText, key[0]);
            res = des.Decrypt(res, key[1]);
            res = des.Encrypt(res, key[1]);
            return res;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
