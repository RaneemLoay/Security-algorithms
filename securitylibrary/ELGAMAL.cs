using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();
            BigInteger Q = new BigInteger(q);
            BigInteger c1 = BigInteger.ModPow(alpha, k, Q);
            BigInteger c2 = BigInteger.ModPow(y, k, Q) * m % Q;
            return new List<long>() { (long)c1, (long)c2 };

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int M;
            BigInteger K = BigInteger.ModPow(c1, x, q);
            ExtendedEuclid eclid = new ExtendedEuclid();
            int invK = eclid.GetMultiplicativeInverse((int)K, q);
            M = (c2 * invK) % q;
            return M;

        }
    }
}
