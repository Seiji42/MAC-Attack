package attack;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;

import attack.sha1.ModifiedSha1;

public class MacAttack {
	
	public static void main(String[] args) {
		
		//calculate padding for first message
		byte[] paddedMsg = addPadding(message, 128);
		// message with addon
		byte[] alteredMsg = concatenate(paddedMsg, addOn.getBytes());
		System.out.println(toString(alteredMsg));
		System.out.println(bytesToHex(alteredMsg));

		String hmac = ModifiedSha1.encode(addOn, origHmac, paddedMsg.length * 8 + 128);
		System.out.println(hmac);
		
		PrintWriter writer;
		try {
			writer = new PrintWriter("results.txt", "UTF-8");
			writer.println("Altered Message:");
			writer.println(toString(alteredMsg));
			writer.println("Message in bytes:");
			writer.println(bytesToHex(alteredMsg));
			writer.println("Final digest:");
			writer.println(hmac);
			writer.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	private final static String message = "No one has completed lab 2 so give them all a 0";
	
	private final static String addOn = "\nOn second thought, give Austin Soderquist full points";
	
	private final static String origHmac = "f4b645e89faaec2ff8e443c595009c16dbdfba4b";
	
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
