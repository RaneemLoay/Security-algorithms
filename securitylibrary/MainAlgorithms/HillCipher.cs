using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        public int GetDeterminant(List<List<int>>a, int n)
        {
            if (n == 1)
                return a[0][0];
            if (n == 2)
                return (a[0][0] * a[1][1]) - (a[0][1] * a[1][0]);
            int d = 0;
            for (int j = 0; j < n; j++)
            {
                List<List<int>> temp = new List<List<int>>();
                for(int k = 1; k < n; k++)
                {
                    List<int> t = new List<int>();
                    for (int l = 0; l < n; l++)
                    {
                        if (l == j)
                            continue;
                        t.Add(a[k][l]);
                    }
                    temp.Add(t);
                }
                d += (int)(a[0][j] * Math.Pow(-1, 0 + j) * GetDeterminant(temp, temp.Count));
            }
            return d;
        }



        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();
            for (int a = 0; a < 26; a++)
            {
                for (int b = 0; b < 26; b++)
                {
                    for (int c = 0; c < 26; c++)
                    {
                        for (int d = 0; d < 26; d++)
                        {
                            key.Add(a);
                            key.Add(b);
                            key.Add(c);
                            key.Add(d);

                            int m = 2;
                            while (true)
                            {
                                if (Math.Log(key.Count, m) == 2)
                                    break;
                                m++;
                            }
                            int[,] pt = new int[m, plainText.Count / m];
                            int count = 0;
                            for (int j = 0; j < plainText.Count / m; j++)
                            {
                                for (int i = 0; i < m; i++)
                                {
                                    pt[i, j] = plainText[count];
                                    count++;
                                }
                            }
                            int[,] k = new int[m, m];
                            count = 0;
                            for (int i = 0; i < m; i++)
                            {
                                for (int j = 0; j < m; j++)
                                {
                                    k[i, j] = key[count];
                                    count++;
                                }
                            }
                            List<int> ciphertext = new List<int>();
                            int[,] ctx = new int[m, plainText.Count / m];
                            for (int i = 0; i < plainText.Count / m; i++)
                            {
                                for (int l = 0; l < m; l++)
                                {
                                    ctx[l, i] = 0;
                                    for (int j = 0; j < m; j++)
                                    {
                                        ctx[l, i] += pt[j, i] * k[l, j];
                                    }
                                    ctx[l, i] = ctx[l, i] % 26;
                                    ciphertext.Add(ctx[l, i]);
                                }
                            }
                            bool e = true;
                            for (int f = 0; f < cipherText.Count; f++)
                            {
                                if (ciphertext[f] != cipherText[f])
                                {
                                    e = false;
                                    break;
                                }
                            }
                            if (e)
                                return key;
                            else
                                key.Clear();
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            for (int i = 0; i < key.Count; i++)
            {
                if (key[i] < 0 || key[i] > 26)
                    throw new Exception();
            }
            int m = 2;
            while (true)
            {
                if (Math.Log(key.Count, m) == 2)
                {
                    break;
                }
                m++;
            }
            int[,] ct = new int[m, cipherText.Count / m];
            int c = 0;
            for (int j = 0; j < cipherText.Count / m; j++)
            {
                for (int i = 0; i < m; i++)
                {
                    ct[i, j] = cipherText[c];
                    c++;
                }
            }
            List<List<int>> k = new List<List<int>>();
            c = 0;
            for (int i = 0; i < m; i++)
            {
                List<int> t = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    t.Add(key[c]);
                    c++;
                }
                k.Add(t);
            }
            int d = GetDeterminant(k, m);
            if (d == 0)
                throw new Exception();
            d = d % 26;
            while (d < 0)
                d += 26;
            int Remainder;
            int n1 = 26;
            int n2 = d;
            while (n1 != 0)
            {
                Remainder = n2 % n1;
                n2 = n1;
                n1 = Remainder;
            }
            if (n2 != 1)
                throw new Exception();
            int b = 1;
            for (int i = 2; i <= 26; i++)
            {
                if ((i * d) % 26 == 1)
                {
                    b = i;
                    break;
                }
            }
            if (b == 1)
                throw new Exception();
            List<List<int>> kI = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> kir = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    List<List<int>> temp = new List<List<int>>();
                    for (int p = 0; p < m; p++)
                    {
                        if (p == i)
                            continue;
                        List<int> te = new List<int>();
                        for (int l = 0; l < m; l++)
                        {
                            if (j == l)
                                continue;
                            te.Add(k[p][l]);
                        }
                        temp.Add(te);
                    }
                    int dt = GetDeterminant(temp, temp.Count) % 26;
                    while (dt < 0)
                        dt += 26;
                    double t = (b * Math.Pow(-1, i + j) * dt) % 26;
                    t = Math.Ceiling(t);
                    while (t < 0)
                        t += 26;
                    kir.Add((int)t);
                }
                kI.Add(kir);
            }
            List<List<int>> kIT = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> kitr = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    kitr.Add(kI[j][i]);
                }
                kIT.Add(kitr);
            }
            List<int> plainText = new List<int>();
            int[,] pt = new int[m, cipherText.Count / m];
            for (int i = 0; i < cipherText.Count / m; i++)
            {
                for (int l = 0; l < m; l++)
                {
                    pt[l, i] = 0;
                    for (int j = 0; j < m; j++)
                    {
                        pt[l, i] += ct[j, i] * kIT[l][j];
                    }
                    pt[l, i] = pt[l, i] % 26;
                    plainText.Add(pt[l, i]);
                }
            }
            return plainText;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = 2;
            while (true)
            {
                if (Math.Log(key.Count, m) == 2)
                {
                    break;
                }
                m++;
            }
            int[,] pt = new int[m, plainText.Count / m];
            int c = 0;
            for (int j = 0; j < plainText.Count / m; j++)
            {
                for (int i = 0; i < m; i++)
                {
                    pt[i, j] = plainText[c];
                    c++;
                }
            }
            int[,] k = new int[m, m];
            c = 0;
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    k[i, j] = key[c];
                    c++;
                }
            }
            List<int> cipherText = new List<int>();
            int[,] ct = new int[m, plainText.Count / m];
            for (int i = 0; i < plainText.Count / m; i++)
            {
                for (int l = 0; l < m; l++)
                {
                    ct[l, i] = 0;
                    for (int j = 0; j < m; j++)
                    {
                        ct[l, i] += pt[j, i] * k[l, j];
                    }

                    ct[l, i] = ct[l, i] % 26;
                    cipherText.Add(ct[l, i]);
                }
            }
            return cipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int[,] ct = new int[3, cipher3.Count / 3];
            int c = 0;
            for (int j = 0; j < 3; j++)
            {
                for (int i = 0; i < cipher3.Count / 3; i++)
                {
                    ct[j, i] = cipher3[c];
                    c++;
                }
            }

            List<List<int>> pt = new List<List<int>>();
            c = 0;
            for (int i = 0; i < 3; i++)
            {
                List<int> t = new List<int>();
                for (int j = 0; j < 3; j++)
                {
                    t.Add(plain3[c]);
                    c++;
                }
                pt.Add(t);
            }
            int d = GetDeterminant(pt, 3);
            if (d == 0)
                throw new Exception();
            d = d % 26;
            while (d < 0)
                d += 26;
            int Remainder;
            int n1 = 26;
            int n2 = d;
            while (n1 != 0)
            {
                Remainder = n2 % n1;
                n2 = n1;
                n1 = Remainder;
            }
            if (n2 != 1)
                throw new Exception();
            int b = 1;
            for (int i = 2; i <= 26; i++)
            {
                if ((i * d) % 26 == 1)
                {
                    b = i;
                    break;
                }
            }
            if (b == 1)
                throw new Exception();
            List<List<int>> ptI = new List<List<int>>();
            for (int i = 0; i < 3; i++)
            {
                List<int> ptIr = new List<int>();
                for (int j = 0; j < 3; j++)
                {
                    List<List<int>> temp = new List<List<int>>();
                    for (int p = 0; p < 3; p++)
                    {
                        if (p == i)
                            continue;
                        List<int> te = new List<int>();
                        for (int l = 0; l < 3; l++)
                        {
                            if (j == l)
                                continue;
                            te.Add(pt[p][l]);
                        }
                        temp.Add(te);
                    }
                    int dt = GetDeterminant(temp, temp.Count) % 26;
                    while (dt < 0)
                        dt += 26;
                    double t = (b * Math.Pow(-1, i + j) * dt) % 26;
                    t = Math.Ceiling(t);
                    while (t < 0)
                        t += 26;
                    ptIr.Add((int)t);
                }
                ptI.Add(ptIr);
            }
            List<List<int>> ptIT = new List<List<int>>();
            for (int i = 0; i < 3; i++)
            {
                List<int> ptitr = new List<int>();
                for (int j = 0; j < 3; j++)
                {
                    ptitr.Add(ptI[j][i]);
                }
                ptIT.Add(ptitr);
            }
            List<int> key = new List<int>();
            int[,] keyy = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int l = 0; l < 3; l++)
                {
                    keyy[l, i] = 0;
                    for (int j = 0; j < 3; j++)
                    {
                        keyy[l, i] += ptIT[l][j] * ct[j, i];
                    }
                    keyy[l, i] = keyy[l, i] % 26;
                    key.Add(keyy[l, i]);
                }
            }
            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
