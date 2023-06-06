using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            char[] alpha = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            char[,] matrix2D = new char[26, 26];
            int counter = 0;
            string key = "", keystream = "";
            //create matrix 26 * 26
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix2D[i, j] = alpha[counter % 26];
                    counter++;
                }
                counter = 1;
                counter += i;
            }
            int index1 = 0, index2 = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                char find_PT_index = plainText[i];
                char find_CT_index = cipherText[i];
                for (int x = 0; x < 26; x++)
                {
                    if (alpha[x] == find_PT_index)
                    {
                        index1 = x;
                    }
                }
                for (int y = 0; y < 26; y++)
                {
                    if (matrix2D[y, index1] == find_CT_index)
                    {
                        index2 = y;
                    }
                }
                keystream += matrix2D[index2, 0];
            }
            int counterr = 0;

            for (int z = 0; z < keystream.Length; z++)
            {
                if (keystream[z] == plainText[counterr])
                {
                    counterr++;
                }
                else
                {
                    counterr = 0;
                }
            }
            key = keystream.Remove(keystream.Length - counterr);
            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string key_Stream = "", p_text = "";
            int diff_Key_KeyStream = cipherText.Length - key.Length;
            key_Stream = key; // assign key to key stream

            /* for (int i = 0; i < diff_Key_KeyStream; i++)
             {
                 key_Stream += key_Stream[i];
             }*/
            char[] alpha = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            char[,] matrix2D = new char[26, 26];
            int counter = 0;
            //create matrix 26 * 26
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix2D[i, j] = alpha[counter % 26];
                    counter++;
                }
                counter = 1;
                counter += i;
            }
            int indexOfCol = 0, indexOfRow = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int a = 0; a < alpha.Length; a++)
                {
                    if (key_Stream[i] == alpha[a])
                    {
                        indexOfRow = a;

                        for (int b = 0; b < 25; b++)
                        {
                            if (matrix2D[a, b] == cipherText[i])
                            {
                                indexOfCol = b;
                                // handeling key_stream 
                                if (key_Stream.Length <= cipherText.Length)
                                {
                                    key_Stream += matrix2D[0, indexOfCol];
                                }
                                break;
                            }
                        }
                    }
                }
                p_text += matrix2D[0, indexOfCol];
            }
            return p_text;
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            //throw new NotImplementedException();
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            string key_Stream = "", EN = "";
            int diff_Key_KeyStream = plainText.Length - key.Length;
            key_Stream = key; // assign key to key stream
            for (int i = 0; i < diff_Key_KeyStream; i++)
            {
                key_Stream += plainText[i];
            }
            char[] alpha = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            char[,] matrix2D = new char[26, 26];
            int counter = 0;
            //create matrix 26 * 26
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix2D[i, j] = alpha[counter % 26];
                    counter++;
                }
                counter = 1;
                counter += i; // shift to the next index
            }
            // Encryption
            int indexOfCol = 0, indexOfRow = 0;
            for (int i = 0; i < key_Stream.Length; i++)
            {
                for (int a = 0; a < alpha.Length; a++)
                {
                    if (alpha[a] == plainText[i])
                    {
                        indexOfCol = a;
                    }
                    if (alpha[a] == key_Stream[i])
                    {
                        indexOfRow = a;
                    }
                }
                EN += matrix2D[indexOfRow, indexOfCol];
            }
            return (EN.ToUpper());
        }
    }
}
