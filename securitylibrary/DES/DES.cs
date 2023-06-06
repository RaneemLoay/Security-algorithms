using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        int[] initial_Perm ={58, 50, 42, 34, 26, 18, 10, 2,
                             60, 52, 44, 36, 28, 20, 12, 4,
                             62, 54, 46, 38, 30, 22, 14, 6,
                             64, 56, 48, 40, 32, 24, 16, 8,
                              57, 49, 41, 33, 25, 17, 9, 1,
                              59, 51, 43, 35, 27, 19, 11, 3,
                               61, 53, 45, 37, 29, 21, 13, 5,
                               63, 55, 47, 39, 31, 23, 15, 7 };

        int[] final_perm = {  40, 8, 48, 16, 56, 24, 64, 32,
                                 39, 7, 47, 15, 55, 23, 63, 31,
                                 38, 6, 46, 14, 54, 22, 62, 30,
                                 37, 5, 45, 13, 53, 21, 61, 29,
                                 36, 4, 44, 12, 52, 20, 60, 28,
                                 35, 3, 43, 11, 51, 19, 59, 27,
                                 34, 2, 42, 10, 50, 18, 58, 26,
                                 33, 1, 41, 9, 49, 17, 57, 25};

        public static int[,] b1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        public static int[,] b2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        public static int[,] b3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        public static int[,] b4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        public static int[,] b5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        public static int[,] b6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        public static int[,] b7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        public static int[,] b8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

        public static Dictionary<int, int[,]> bs = new Dictionary<int, int[,]>()
        {
            [1] = b1,
            [2] = b2,
            [3] = b3,
            [4] = b4,
            [5] = b5,
            [6] = b6,
            [7] = b7,
            [8] = b8,
        };

        int[] pc1 = { 57,  49, 41,  33,  25,  17,  9,
                      1,   58,  50,  42,  34,  26,  18,
                      10,  2,   59,  51,  43,  35,  27,
                      19,  11,  3,   60,  52,  44,  36,
                      63,  55,  47,  39,  31,  23,  15,
                      7,   62,  54,  46,  38,  30,  22,
                      14,  6,   61,  53,  45,  37,  29,
                      21,  13,  5,   28,  20,  12,  4};

        int[] PC_2 ={
                 14, 17, 11, 24, 1, 5 ,
                 3, 28, 15, 6, 21, 10 ,
                 23, 19, 12, 4, 26, 8 ,
                 16, 7, 27, 20, 13, 2 ,
                 41, 52, 31, 37, 47, 55 ,
                 30, 40, 51, 45, 33, 48 ,
                 44, 49, 39, 56, 34, 53 ,
                 46, 42, 50, 36, 29, 32  };

        int[] noOfShiftLeft = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        public int[] ShiftLeft(int[] shift, int n)
        {
            int[] s = new int[shift.Length - n];
            int[] l = new int[n];
            int[] shifted = { };

            for (int i = n; i < shift.Length; i++)
            {
                s[i - n] = shift[i];
            }
            for (int i = 0; i < n; i++)
            {
                l[i] = shift[i];
            }
            shifted = s.Concat(l).ToArray();

            return shifted;

        }

        public int[][] subKeysGeneration(string key)
        {
            int[] subkey = HextoInt(key);
            int[] k = new int[56];
            int[] d0 = new int[28];
            int[] c0 = new int[28];

            for (int i = 0; i < 56; i++)
            {
                k[i] = subkey[pc1[i] - 1];
            }
            for (int i = 0; i < k.Length; i++)
            {
                if (i <= 27)
                {
                    c0[i] = k[i];
                }
                else
                {
                    d0[i - 28] = k[i];
                }
            }
            int[][] c = new int[16][];
            int[][] d = new int[16][];

            c[0] = ShiftLeft(c0, noOfShiftLeft[0]);
            d[0] = ShiftLeft(d0, noOfShiftLeft[0]);
            for (int i = 1; i < 16; i++)
            {
                c[i] = ShiftLeft(c[i - 1], noOfShiftLeft[i]);
                d[i] = ShiftLeft(d[i - 1], noOfShiftLeft[i]);
            }

            int[][] key_48 = new int[16][];
            int[][] key_56 = new int[16][];

            for (int i = 0; i < 16; i++)
            {
                key_56[i] = new int[56];
                Array.Copy(c[i], 0, key_56[i], 0, 28);
                Array.Copy(d[i], 0, key_56[i], 28, 28); // making 56 bits keys
            }

            for (int i = 0; i < 16; i++)
            {
                int[] currKey = new int[48];
                for (int j = 0; j < 48; j++)
                {
                    currKey[j] = key_56[i][PC_2[j] - 1]; // making 48 bits keys
                }
                key_48[i] = currKey;
            }
            return key_48;
        }
        public static int[] Sbox(int[] KplusER)
        {
            int[,] blocks = new int[8, 6];
            int cnt = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    blocks[i, j] = KplusER[cnt];
                    cnt++;
                }
            }

            string[] newBlocks = new string[8];

            int row, col;
            for (int i = 0; i < 8; i++)
            {
                int[] r = new int[2];

                r[0] = blocks[i, 0];
                r[1] = blocks[i, 5];

                string roww = string.Join("", r);
                string coll = "";
                row = Convert.ToInt32(roww, 2);
                for (int j = 1; j < 5; j++)
                {
                    coll += blocks[i, j];
                }
                col = Convert.ToInt32(coll, 2);

                newBlocks[i] = Convert.ToString(bs[i + 1][row, col], 2);
                while (newBlocks[i].Length < 4)
                {
                    newBlocks[i] = '0' + newBlocks[i];
                }

            }
            int[] S = new int[32];
            int count = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    S[count] = Convert.ToInt32(newBlocks[i][j]) - 48;
                    count++;
                }
            }

            return S;
        }
        public int[] F(int[] right, int[] subKey)
        {
            int[] E_R = new int[48];
            int[] XOR = new int[48];
            int[] S_box;
            int[] F = new int[32];
            int[] E_Bit_Selection = { 32, 1, 2, 3, 4, 5,
                                 4, 5, 6, 7, 8, 9,
                                 8, 9, 10, 11, 12, 13,
                                 12, 13, 14, 15, 16, 17,
                                 16, 17, 18, 19, 20, 21,
                                 20, 21, 22, 23, 24, 25,
                                 24, 25, 26, 27, 28, 29,
                                 28, 29, 30, 31, 32, 1};

            int[] perm = { 16, 7, 20, 21,
                        29, 12, 28, 17,
                        1, 15, 23, 26,
                        5, 18, 31, 10,
                        2, 8, 24, 14,
                        32, 27, 3, 9,
                        19, 13, 30, 6,
                        22, 11, 4, 25};

            for (int i = 0; i < 48; i++)
            {
                E_R[i] = right[E_Bit_Selection[i] - 1];
            }
            for (int i = 0; i < 48; i++)
            {
                XOR[i] = (!(E_R[i] == subKey[i])) ? 1 : 0;
            }
            S_box = Sbox(XOR);

            for (int i = 0; i < 32; i++)
            {
                F[i] = S_box[perm[i] - 1];
            }
            return F;
        }
        public int[] HextoInt(string hex)
        {
            hex = hex.Remove(0, 2);
            Dictionary<char, string> hextoint = new Dictionary<char, string>()
            {
                ['0'] = "0000",
                ['1'] = "0001",
                ['2'] = "0010",
                ['3'] = "0011",
                ['4'] = "0100",
                ['5'] = "0101",
                ['6'] = "0110",
                ['7'] = "0111",
                ['8'] = "1000",
                ['9'] = "1001",
                ['A'] = "1010",
                ['B'] = "1011",
                ['C'] = "1100",
                ['D'] = "1101",
                ['E'] = "1110",
                ['F'] = "1111",
            };
            int size = hex.Length * 4;
            int indx = 0;
            int[] binaryint = new int[hex.Length * 4];
            for (int i = 0; i < hex.Length; i++)
            {
                string int4 = hextoint[hex[i]];
                for (int j = 0; j < 4; j++)
                {
                    binaryint[indx] = int4[j] - 48;
                    indx++;
                }
            }
            return binaryint;
        }
        public string InttoHex(int[] binaryint)
        {
            string bti = "";
            for (int i = 0; i < 64; i++)
            {
                bti += Convert.ToString(binaryint[i]);
            }
            Dictionary<string, string> inttohexmap = new Dictionary<string, string>()
            {
                ["0000"] = "0",
                ["0001"] = "1",
                ["0010"] = "2",
                ["0011"] = "3",
                ["0100"] = "4",
                ["0101"] = "5",
                ["0110"] = "6",
                ["0111"] = "7",
                ["1000"] = "8",
                ["1001"] = "9",
                ["1010"] = "A",
                ["1011"] = "B",
                ["1100"] = "C",
                ["1101"] = "D",
                ["1110"] = "E",
                ["1111"] = "F",
            };
            string hex = "";
            for (int i = 0; i < binaryint.Length; i += 4)
            {
                string key;
                key = bti.Substring(i, 4);
                hex += inttohexmap[key];
            }
            hex = "0x" + hex;
            return hex;
        }
        public override string Decrypt(string cipherText, string key)
        {

            int[] CT = HextoInt(cipherText);
            int[][] subKeys = subKeysGeneration(key);
            int[] M = new int[64];
            int[] C = new int[64];
            //initial permutation
            for (int i = 0; i < 64; i++)
            {
                C[final_perm[i] - 1] = CT[i];
            }
            int[] left = new int[32];
            int[] right = new int[32];
            //swapping
            Array.Copy(C, 0, right, 0, 32);
            Array.Copy(C, 32, left, 0, 32);

            //16 round

            for (int round = 15; round >= 0; round--)
            {
                int[] nextright = left;
                int[] nextleft = new int[32];
                int[] f = F(left, subKeys[round]);
                for (int i = 0; i < 32; i++)
                {
                    nextleft[i] = (!(right[i] == f[i])) ? 1 : 0;
                }
                left = nextleft;
                right = nextright;
            }
            Array.Copy(left, 0, C, 0, 32);
            Array.Copy(right, 0, C, 32, 32);

            //final permutaion
            for (int i = 0; i < 64; i++)
            {
                M[initial_Perm[i] - 1] = C[i];
            }
            return InttoHex(M);
        }

        public override string Encrypt(string plainText, string key)
        {
            int[] PT = HextoInt(plainText);

            int[][] subKeys = subKeysGeneration(key);
            int[] M = new int[64];
            int[] C = new int[64];
            //initial permutation
            for (int i = 0; i < 64; i++)
            {
                M[i] = PT[initial_Perm[i] - 1];
            }
            int[] left = new int[32];
            int[] right = new int[32];
            Array.Copy(M, 0, left, 0, 32);
            Array.Copy(M, 32, right, 0, 32);

            //16 round 

            for (int round = 0; round < 16; round++)
            {
                int[] f = F(right, subKeys[round]);
                int[] newleft = right;
                int[] newright = new int[32];
                for (int i = 0; i < 32; i++)
                {
                    newright[i] = (!(left[i] == f[i])) ? 1 : 0;
                }
                left = newleft;
                right = newright;
            }

            //swapping
            Array.Copy(right, 0, M, 0, 32);
            Array.Copy(left, 0, M, 32, 32);

            //final permutation
            for (int i = 0; i < 64; i++)
            {
                C[i] = M[final_perm[i] - 1];
            }
            string cipher = InttoHex(C);
            return cipher;
        }

    }
}