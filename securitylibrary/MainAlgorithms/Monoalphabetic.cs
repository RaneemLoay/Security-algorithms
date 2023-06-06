using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            string alphabetic = "abcdefghijklmnopqrstuvwxyz";
            StringBuilder notFound = new StringBuilder();
            StringBuilder key = new StringBuilder();
            for (int i = 0; i < 26; i++)
            {
                if (plainText.Contains(alphabetic[i]))
                {
                    int indx = plainText.IndexOf(alphabetic[i]);
                    key.Append(cipherText[indx]);

                }
                else
                {
                    key.Append(' ');

                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (!cipherText.Contains(alphabetic[i]))
                {

                    notFound.Append(alphabetic[i]);

                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (key[i] == ' ')
                {
                    key[i] = notFound[0];
                    notFound.Remove(0, 1);
                }
            }

            return key.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string alphabetic = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, char> permutation = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                permutation[key[i]] = alphabetic[i];    // mapping the alphabetic permutation (reversed)
            }

            StringBuilder plainText = new StringBuilder();
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText.Append(permutation[cipherText[i]]);
            }
            return plainText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            string alphabetic = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, char> permutation = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                permutation[alphabetic[i]] = key[i];    // mapping the alphabetic permutation
            }

            StringBuilder cipherText = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText.Append(permutation[plainText[i]]);
            }
            return cipherText.ToString();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string freqAlphabetic = "etaoinsrhldcumfpgwybvkxjqz";
            Dictionary<char, int> frequency = new Dictionary<char, int>();  // frequency of cipher chars
            Dictionary<char, char> PcharCchar = new Dictionary<char, char>(); //mapping plain text & cipher text chars

            for (int i = 0; i < cipher.Length; i++)
            {
                if (frequency.ContainsKey(cipher[i]))
                {
                    frequency[cipher[i]]++;
                }
                else
                {
                    frequency[cipher[i]] = 1;
                }
            }

            int freqIndx = 0;
            foreach (KeyValuePair<char, int> alpha in frequency.OrderByDescending(key => key.Value))
            {
                PcharCchar[alpha.Key] = freqAlphabetic[freqIndx];
                freqIndx++;
            }
            StringBuilder plainText = new StringBuilder();

            for (int i = 0; i < cipher.Length; i++)
            {
                plainText.Append(PcharCchar[cipher[i]]);
            }

            return plainText.ToString();

        }
    
    }
}