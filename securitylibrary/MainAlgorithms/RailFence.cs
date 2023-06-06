using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int key = 0;
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            for (int i = 1; i < plainText.Length; i++)
            {
                if (cipherText[2] == plainText[i])
                {
                    key = i;
                    break;
                }
            }

            key = key / 2;
            return key;

        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            string plaintext = "";

            int pos = 0;
            int col = (int)Math.Ceiling((double)cipherText.Length / (double)key);

            char[,] matrix = new char[key, col];
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (pos < cipherText.Length)
                    {
                        matrix[i, j] = cipherText[pos];

                    }
                    else
                    {
                        matrix[i, j] = '\n';
                    }

                    pos++;
                }
            }
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (matrix[j, i] != '\n')
                        plaintext += matrix[j, i];
                }
            }
            return plaintext;
        }

        public string Encrypt(string plainText, int key)
        {
            //  throw new NotImplementedException();
            string cipherText = "";

            int pos = 0;

            char[,] matrix = new char[key, plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (pos < plainText.Length)
                    {
                        matrix[j, i] = plainText[pos];
                    }
                    else
                    {
                        matrix[j, i] = '\n';
                    }
                    pos++;
                }
            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < plainText.Length; j++)
                {
                    if (matrix[i, j] != '\n')
                        cipherText += matrix[i, j];
                }

            }
            return cipherText;
        }
    }
}
