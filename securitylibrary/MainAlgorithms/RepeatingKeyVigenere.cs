using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            cipherText = cipherText.ToLower();
            // find the key-stream
            for (int i = 0; i < cipherText.Length; i++)
            {
                key += Convert.ToChar((Convert.ToInt16(26 + cipherText[i] - plainText[i]) % 26) + 97);
            }

            // find the keyword with the correct length
            int lenght = 1;
            bool trueLength = false;
            while (true)
            {
                for (int i = 0; i < key.Length - lenght; i++)
                {
                    if (key[i] != key[i + lenght])
                    {
                        break;
                    }
                    if (i == key.Length - lenght - 1)
                    {
                        trueLength = true;
                    }
                }
                if (trueLength == true)
                {
                    key = key.Remove(lenght);
                    break;
                }
                else
                {
                    lenght++;
                }

            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += Convert.ToChar((Convert.ToInt16(26 + cipherText[i] - key[i % key.Length]) % 26) + 97);
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += Convert.ToChar(((Convert.ToInt16(plainText[i]) - 97 + key[i % key.Length] - 97) % 26) + 65);
            }
            return cipherText;
        }
    }
}