package attack;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import attack.sha1.ModifiedSha1;
import attack.sha1.SHA1;

/**
 * This class was used for testing my ModifiedSha1 class to make sure it would give me the correct results
 * @author Austin
 *
 */
public class FakeExample {

	public static void main(String[] args) {		
		//setup
		byte[] msg = concatenate(key, message.getBytes());
		System.out.println(toString(msg));
		firstMAC = SHA1.encode(msg);
		System.out.println(firstMAC);
		
		//calculate padding for first message
		byte[] paddedMsg = addPadding(message, key.length * 8);
		System.out.println(toString(paddedMsg));
		
		// message with addon
		byte[] alteredMsg = concatenate(paddedMsg, addOn.getBytes());
		System.out.println(toString(alteredMsg));
		
		// digest for message with addon
		secondMAC = ModifiedSha1.encode(addOn, firstMAC, paddedMsg.length * 8 + 128);
		System.out.println(secondMAC);
		byte[] finalMessage = addPadding(toString(alteredMsg), key.length * 8);
		System.out.println(toString(finalMessage));
		
		// test message with addon and key
		byte[] lastMsg = concatenate(key, alteredMsg);
		finalMAC = SHA1.encode(lastMsg);
		System.out.println(finalMAC);
	}
	
	private final static byte[] key = {
			0x45, (byte)0x8B, 0x7A, 0x5E,
			0x45, 0x7B, 0x7A, 0x5E,
			0x45, 0x7B, 0x7A, 0x5E,
			0x45, 0x7B, 0x7A, 0x5E
	};
	
	private final static String message = "No one has completed lab 2 so give them all a 0";
	
	private final static String addOn = "\nOn second thought, give Austin Soderquist full points";
	
	private static String firstMAC;

	private static String secondMAC;

	private static String finalMAC;
	
	public static String toString(byte[] bytes) {
		return new String(bytes);
	}
	
	public static byte[] concatenate(byte[] a, byte[] b) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		try {
			outputStream.write( a );
			outputStream.write( b );
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return outputStream.toByteArray( );
	}

	public static byte[] addPadding(String message, int keyLen) {
		byte[] x = message.getBytes();
        int[] blks = new int[(((x.length + 8 + (keyLen / 8)) >> 6) + 1) * 16 - (keyLen / 8 / 4)];
        int i;

        for(i = 0; i < x.length; i++) {
            blks[i >> 2] |= (x[i] & 0xff) << (24 - (i % 4) * 8);
        }

        blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
        blks[blks.length - 1] = x.length * 8 + keyLen;
		
		byte[] result = {};
		
		for (i = 0; i < blks.length; i++) {
			byte[] data = ByteBuffer.allocate(4).putInt(blks[i]).array();
			result = concatenate(result, ByteBuffer.allocate(4).putInt(blks[i]).array());
		}
		return result;
	}
}
