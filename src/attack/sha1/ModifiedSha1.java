package attack.sha1;
/**
 * Based on code found in SHA1.java
 * 
 * Some functions are taken directly from the file.
 * 
 * This class was created to perform a length extension attack.
 * @author Austin
 *
 */
public class ModifiedSha1 {

    /*
     * Bitwise rotate a 32-bit number to the left
     */
    private static int rol(int num, int cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    /*
     * Take a string and return the base64 representation of its SHA-1.
     */
    public static String encode(String appendedMessage, String previousHash, int prevMessageLength) {

        // Convert a string to a sequence of 16-word blocks, stored as an array.
        // Append padding bits and the length, as described in the SHA1 standard
    	byte[] x = appendedMessage.getBytes();
        int[] blks = new int[(((x.length + 8) >> 6) + 1) * 16];
        int i;

        for(i = 0; i < x.length; i++) {
            blks[i >> 2] |= (x[i] & 0xff) << (24 - (i % 4) * 8);
        }

        blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
        blks[blks.length - 1] = x.length * 8 + prevMessageLength; // add original message length

        // calculate 160 bit SHA1 hash of the sequence of blocks

        int[] w = new int[80];

        // get values from string
        int a = (int)Long.parseLong(previousHash.substring( 0,  8), 16);
        int b = (int)Long.parseLong(previousHash.substring( 8, 16), 16);
        int c = (int)Long.parseLong(previousHash.substring(16, 24), 16);
        int d = (int)Long.parseLong(previousHash.substring(24, 32), 16);
        int e = (int)Long.parseLong(previousHash.substring(32)    , 16);

        for(i = 0; i < blks.length; i += 16) {
            int olda = a;
            int oldb = b;
            int oldc = c;
            int oldd = d;
            int olde = e;

            for(int j = 0; j < 80; j++) {
                w[j] = (j < 16) ? blks[i + j] :
                       ( rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1) );

                int t = rol(a, 5) + e + w[j] +
                   ( (j < 20) ?  1518500249 + ((b & c) | ((~b) & d))
                   : (j < 40) ?  1859775393 + (b ^ c ^ d)
                   : (j < 60) ? -1894007588 + ((b & c) | (b & d) | (c & d))
                   : -899497514 + (b ^ c ^ d) );
                e = d;
                d = c;
                c = rol(b, 30);
                b = a;
                a = t;
              }

              a = a + olda;
              b = b + oldb;
              c = c + oldc;
              d = d + oldd;
              e = e + olde;
          }
        StringBuilder str = new StringBuilder();
        str.append(String.format("%08X", a));
        str.append(String.format("%08X", b));
        str.append(String.format("%08X", c));
        str.append(String.format("%08X", d));
        str.append(String.format("%08X", e));
          return str.toString();
    }
}
