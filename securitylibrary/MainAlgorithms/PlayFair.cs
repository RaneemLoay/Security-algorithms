using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            int f_char_r = 0, f_char_c = 0, s_char_r = 0, s_char_c = 0;
            key = key.ToLower();
            cipherText = cipherText.ToLower();
            char[,] keymatrix = new char[5, 5];
            List<string> plain = new List<string>();
            string alpha = "";
            for (char c = 'a'; c <= 'z'; c++)
            {
                if (c == 'j')
                    continue;
                alpha += c;
            }
            var uniquekey = new HashSet<char>(key);
            key = "";
            foreach (char c in uniquekey)
                key += c;
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == 'j')
                {
                    key = key.Substring(0, i) + "" + key.Substring(i + 1);
                }
            }
            for (int i = 0; i < key.Length; i++)
            {
                for (int j = 0; j < alpha.Length; j++)
                {
                    if (key[i] == alpha[j])
                    {
                        alpha = alpha.Substring(0, j) + "" + alpha.Substring(j + 1);
                    }
                }
            }
            string text = key + alpha;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    keymatrix[i, j] = text[i * 5 + j];
                }
            }
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                //search for each two chars in the matrix 
                for (int r = 0; r < 5; r++)
                {
                    for (int c = 0; c < 5; c++)
                    {
                        if (cipherText[i] == keymatrix[r, c])
                        {
                            f_char_r = r;
                            f_char_c = c;
                        }
                        else if (cipherText[i + 1] == keymatrix[r, c])
                        {
                            s_char_r = r;
                            s_char_c = c;
                        }
                    }
                }
                if (f_char_r == s_char_r) //in same row
                {
                    plain.Add(keymatrix[f_char_r, (f_char_c - 1 + 5) % 5] + "" + keymatrix[s_char_r, (s_char_c - 1 + 5) % 5]);
                }
                else if (f_char_c == s_char_c) // in same column
                {
                    plain.Add(keymatrix[(f_char_r - 1 + 5) % 5, f_char_c] + "" + keymatrix[(s_char_r - 1 + 5) % 5, s_char_c]);
                }
                else
                {
                    plain.Add(keymatrix[f_char_r, s_char_c] + "" + keymatrix[s_char_r, f_char_c]);
                }
            }
            string plaint = "";
            for (int i = 0; i < plain.Count; i++)
            {
                if ((plain[i][1] == 'x' && i == plain.Count - 1) || (plain[i][1] == 'x' && i != plain.Count - 1 && plain[i][0] == plain[i + 1][0]))
                {
                    plaint += plain[i][0];
                    continue;
                }
                plaint += plain[i];
            }
            return plaint;
        }

        public string Encrypt(string plainText, string key)
        {
            key = key.ToLower();
            var uniquekey = new HashSet<char>(key);
            key = "";
            foreach (char c in uniquekey)
                key += c;
            char[,] keymatrix = new char[5, 5] { {' ',' ',' ',' ',' '},
                                                   {' ',' ',' ',' ',' '},
                                                   {' ',' ',' ',' ',' '},
                                                   {' ',' ',' ',' ',' '},
                                                   {' ',' ',' ',' ',' '} };

            List<char> alpha = new List<char>();
            for (char c = 'a'; c <= 'z'; c++)
            {
                if (c == 'j')
                    continue;
                alpha.Add(c);
            }
            int k = 0, a = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (k < key.Length && key[k] == 'j')
                    {
                        keymatrix[i, j] = 'i';
                        k++;
                    }
                    else if (k < key.Length)
                    {
                        keymatrix[i, j] = key[k];
                        alpha.Remove(key[k]);
                        k++;
                    }
                    else if (k == key.Length && i < 5 && j < 5)
                    {
                        keymatrix[i, j] = alpha[a];
                        a++;
                    }
                }
            }
            List<string> plain = new List<string>();
            List<string> cipher = new List<string>();
            int dublicate = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (i != plainText.Length - 1 && plainText[i] == plainText[i + 1])
                    dublicate++;
            }
            bool odd;
            if ((plainText.Length + dublicate) % 2 == 0)
                odd = false;
            else
                odd = true;
            for (int i = 0; i < plainText.Length; i++)
            {
                if ((i != plainText.Length - 1 && plainText[i] == plainText[i + 1]) || (odd && i == plainText.Length - 1))
                {
                    plain.Add(plainText[i] + "x");
                    continue;
                }
                plain.Add(plainText[i] + "" + plainText[i + 1]);
                i++;
            }
            for (int i = 0; i < plain.Count; i++)
            {
                int indi1 = 0, indj1 = 0, indi2 = 0, indj2 = 0;
                for (int j = 0; j < 5; j++)
                {
                    for (int l = 0; l < 5; l++)
                    {
                        if (keymatrix[j, l] == plain[i][0])
                        {
                            indi1 = j;
                            indj1 = l;
                        }
                        else if (keymatrix[j, l] == plain[i][1])
                        {
                            indi2 = j;
                            indj2 = l;
                        }
                    }
                }
                if (indi1 == indi2) //two letters in the same row
                {
                    cipher.Add(keymatrix[indi1, (indj1 + 1) % 5] + "" + keymatrix[indi2, (indj2 + 1) % 5]);
                }
                else if (indj1 == indj2)//two letters in the same column
                {
                    cipher.Add(keymatrix[(indi1 + 1) % 5, indj1] + "" + keymatrix[(indi2 + 1) % 5, indj2]);
                }
                else
                {
                    cipher.Add(keymatrix[indi1, indj2] + "" + keymatrix[indi2, indj1]);
                }
            }
            string ciphe = "";
            for (int i = 0; i < cipher.Count; i++)
            {
                ciphe += cipher[i];
            }
            return ciphe;
        }
    }
}