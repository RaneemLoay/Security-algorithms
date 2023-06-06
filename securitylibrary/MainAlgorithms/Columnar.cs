using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int columns = 0;

            int firsletter = 0, secondletter = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (cipherText[0] == plainText[i])
                {
                    firsletter = i;
                    for (int j = firsletter + 1; j < plainText.Length - i; j++)
                    {
                        if (cipherText[1] == plainText[j])
                        {
                            secondletter = j;
                            break;

                        }
                    }

                }
                columns = secondletter - firsletter;
                if (columns > 2)
                {
                    break;
                }
            }

            int Row = plainText.Length / columns;
            if (Row * columns != plainText.Length)
            {
                Row++;
            }

            List<int> key = new List<int>(columns);
            char[,] Matrix_plain_text = new char[Row, columns];
            int plain_text_count = 0;

            //putting plaintext into matrix

            for (int i = 0; i < Row; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    if (plain_text_count < plainText.Length)
                    {
                        Matrix_plain_text[i, j] = plainText[plain_text_count];
                        plain_text_count++;
                    }
                    else
                    {
                        Matrix_plain_text[i, j] = 'X';
                    }
                }
            }

            // putting cipher text in matrix 

            char[,] matrix_cipher_text = new char[Row, columns];
            int cipher_text_count = 0;
            int change_Row_cipher_text = 0;
            int found = 0;
            cipher_text_count = 0;
            for (int col_cipher = 0; col_cipher < columns; col_cipher++)
            {
                found = 0;
                for (int row_cipher = change_Row_cipher_text; row_cipher < Row; row_cipher++)
                {
                    if (cipher_text_count < cipherText.Length)
                    {
                        matrix_cipher_text[row_cipher, col_cipher] = cipherText[cipher_text_count];
                        cipher_text_count++;
                    }
                    if (row_cipher == Row - 1)
                    {
                        for (int col_plain = 0; col_plain < columns; col_plain++)
                        {
                            if (matrix_cipher_text[Row - 1, col_cipher] == Matrix_plain_text[Row - 1, col_plain])
                            {
                                found = 1;
                                break;
                            }

                        }
                        if (found == 0 && col_cipher + 1 < columns)
                        {
                            char oldChar_matrix = matrix_cipher_text[row_cipher, col_cipher];

                            matrix_cipher_text[row_cipher, col_cipher] = 'X';
                            matrix_cipher_text[0, col_cipher + 1] = oldChar_matrix;
                            change_Row_cipher_text = 1;
                        }
                        else if (found == 1)
                        {
                            change_Row_cipher_text = 0;
                        }
                    }
                }
            }

            if (matrix_cipher_text[Row - 1, columns - 1] == '\0')
            {
                matrix_cipher_text[Row - 1, columns - 1] = 'X';
            }

            int size = 0;
            int save = 0;

            for (int col_plain = 0; col_plain < columns; col_plain++)
            {
                for (int col_cipher = 0; col_cipher < columns; col_cipher++)
                {
                    for (int rows = 0; rows < Row; rows++)
                    {
                        if (Matrix_plain_text[rows, col_plain] == matrix_cipher_text[rows, col_cipher])
                        {
                            save = col_cipher;
                            size++;
                            if (size == Row)
                            {
                                key.Add(save + 1);

                            }
                        }
                        else
                        {
                            size = 0;
                            rows = Row;
                        }
                    }
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int Column = key.Count;
            int Row = cipherText.Length / Column;

            char[,] Matrix_2d = new char[Row, Column];

            int c = 1, count = 0;
            for (int i = 0; i < Column; i++)
            {
                if (c == key[i] && c <= key.Count)
                {
                    for (int j = 0; j < Row; j++)
                    {
                        if (count <= cipherText.Length)
                        {
                            Matrix_2d[j, i] = cipherText[count];
                            count++;
                        }
                    }
                    c++;
                    i = -1;
                }
            }
            string plain_text = "";
            for (int i = 0; i < Row; i++)
            {
                for (int j = 0; j < Column; j++)
                {
                    plain_text += Matrix_2d[i, j];
                }
            }
            return plain_text.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int Column = key.Count;
            int Row = plainText.Length / Column;
            if (Row * Column != plainText.Length)
            {
                Row++;
            }

            char[,] Matrix_2d = new char[Row, Column];
            int plain_text_index = 0;

            // putting plain text in matrix 
            for (int i = 0; i < Row; i++)
            {
                for (int j = 0; j < Column; j++)
                {
                    if (plain_text_index < plainText.Length)
                    {

                        Matrix_2d[i, j] = plainText[plain_text_index];
                        plain_text_index++;
                    }
                    else
                    {
                        Matrix_2d[i, j] = 'x';
                    }
                }
            }
            string cipher_Text = "";
            int c = 1;
            for (int i = 0; i < Column; i++)
            {
                if (c == key[i] && c <= key.Count)
                {
                    for (int j = 0; j < Row; j++)
                    {
                        cipher_Text += Matrix_2d[j, i];
                    }
                    c++;
                    i = -1;
                }
            }
            return cipher_Text.ToUpper();

        }

    }
}

