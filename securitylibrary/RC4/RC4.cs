using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        int[] Sarray = new int[256];
        int[] Tarray = new int[256];

        public void InitializeSandT(string key)
        {
            int klen = key.Length;
            for (int i = 0; i < 256; i++)
            {
                Sarray[i] = i;

                Tarray[i] = key[i % klen];
            }
        }

        public void InitialPermutation()
        {
            int perm = 0;
            for (int i = 0; i < 255; i++)
            {
                perm = (perm + Sarray[i] + Tarray[i]) % 256;
                int temp = Sarray[i];
                Sarray[i] = Sarray[perm];
                Sarray[perm] = temp;
            }
        }

        public string StreamGeneration(string input)
        {
            int i = 0;
            int j = 0;

            int K = 0;
            char[] res = new char[input.Length];
            for (int idx = 0; idx < input.Length; idx++)
            {
                i = (i + 1) % 256;
                j = (j + Sarray[i]) % 256;

                int temp = Sarray[i];
                Sarray[i] = Sarray[j];
                Sarray[j] = temp;

                int t = (Sarray[i] + Sarray[j]) % 256;
                K = Sarray[t];

                res[idx] = (char)(input[idx] ^ K);

            }
            string output = new string(res);
            return output;
        }

        public string toChar(string hex)
        {
            string chars = "";
            for (int i = 2; i < hex.Length; i += 2)
            {
                chars += char.ConvertFromUtf32(Convert.ToInt32(hex[i].ToString() + hex[i + 1].ToString(), 16));
            }
            return chars;
        }

        public string toHex(string chars)
        {
            string hex = "0x";
            for (int i = 0; i < chars.Length; i++)
            {
                hex += Convert.ToByte(chars[i]).ToString("x2");
            }
            return hex;
        }
        public override string Decrypt(string cipherText, string key)
        {
            bool hex = false;
            if (cipherText[0] == '0' && cipherText[1] == 'x')
            {
                cipherText = toChar(cipherText);
                key = toChar(key);
                hex = true;
            }
            InitializeSandT(key);
            InitialPermutation();
            string PT = StreamGeneration(cipherText);

            if (hex)
            {
                PT = toHex(PT);
            }
            return PT;

        }

        public override string Encrypt(string plainText, string key)
        {
            bool hex = false;
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                plainText = toChar(plainText);
                key = toChar(key);
                hex = true;
            }
            InitializeSandT(key);
            InitialPermutation();
            string CT = StreamGeneration(plainText);

            if (hex)
            {
                CT = toHex(CT);
            }
            return CT;
        }
    }
}
