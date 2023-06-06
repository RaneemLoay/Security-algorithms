using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {



        //public key of a  = alpha ^Xa % q
        //key = (public key of b ) ^Xa % q


        /////////////////////////////////////////

        //public key of b  = alpha ^Xb % q
        //key = (public key of a ) ^Xb % q



        public int get_Key(int alpha, int q, int x, int y)
        {
            int result = 1;
            int h = 1;
            for(int i=0; i<y; i++)
            {

                h = (alpha * h) % q;

            }


            // power 
   
            for (int i = 0; i < x; i++)
            {

                result = (h * result) % q;


            }


            return result;
        }


        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
           
            List<int> K = new List<int>();

            int K_1 = get_Key(alpha, q, xa, xb);

            int K_2 = get_Key(alpha, q, xb, xa);

            K.Add(K_1);

            K.Add(K_2);

            return K;
        }
    }
}