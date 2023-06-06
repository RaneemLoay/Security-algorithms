using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {

            int x = number;
            int m = baseN;

            int A1 = 1;
            int A2 = 0;
            int A3 = m;
            int B1 = 0;
            int B2 = 1;
            int B3 = x;


            while(B3 != 0 && B3 != 1)
            {
                int Q = A3 / B3;
                int T1 = A1 - (Q * B1);
                int T2 = A2 - (Q * B2);
                int T3 = A3 - (Q * B3);

                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = T1;
                B2 = T2;
                B3 = T3;
            }

            if(B3 == 0)

            {
                return -1;
            }

            else if  (B3 == 1)
            {

                // if (B2 < 0) >>  B2 = B2 + b;
                B2 = B2 < -1 ? B2 + baseN : B2;
                return B2;



            }

            return - 1;

        }
    }
}