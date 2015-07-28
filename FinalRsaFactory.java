import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.util.Random;


public class FinalRsaFactory {
	
    public static void main(String[] args) {
        BigInteger[] keys = new BigInteger[3];
        keys = GenKey(1024);
        BigInteger ku = keys[0];
        BigInteger kp = keys[1];
        BigInteger n = keys[2];
        
        Encrypt(n, ku, "generic.txt");
        
        String nn = n.toString();
        String dd = kp.toString();
        Decrypt(nn, dd, "enc.txt", "after.txt");
        
    }
	
	/**
	 * GenKey 
	 *
	 * Generates private, public, and mod overall values for encryption/decrytption
	 *
	 * @param ks
	 * @return
	 */
	protected static BigInteger[] GenKey(int keySize){
	     
		// key size
		int size = keySize;
		// array that is returned with ku and kr
		BigInteger[] keys = new BigInteger[3];
		
		// random number required gen probable prime
		Random r = new Random();
		
		// -----------------------------------------------------
		// follow the basic formula for RSA
		// -----------------------------------------------------
		
		// select p
		// bit length "size/2", 
		// The bit length of "n" is about 2 times of the bit length of "p".
		// Probable Prime requires a random number generator
		BigInteger p = BigInteger.probablePrime(size/2,r);
		//System.out.println("p: "+p);
		
		// select q
		// nextProbablePrime will generate a different prime
		BigInteger q = p.nextProbablePrime();
		//System.out.println("q: "+q);
		
		// multiply to get n
		BigInteger n = p.multiply(q);
		//System.out.println("mod: "+n);
		
		// now find phi
		// basic definition
		BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		//System.out.println("m: "+m);
		
		// select ku e such that it is positive int, 0 <e <m, gcd(m,e) = 1
		Random r2 = new Random();
	    int length = m.bitLength()-1;
	    BigInteger e = BigInteger.probablePrime(length,r2);
	    // ku we need to loop until (m.gcd(e)).equals(BigInteger.ONE).
	    while (! (m.gcd(e)).equals(BigInteger.ONE) ) {
	    	e = BigInteger.probablePrime(length,r2);
	    }
		//System.out.println("ku: "+e);
		
		// kr d is mod inverse of e
		BigInteger d = e.modInverse(m);
		//System.out.println("kr: "+d);
		//System.out.println("Key size: "+n.bitLength());
		
		keys[0] = e;
		keys[1] = d;
		keys[2] = n;
		
		return keys;
	}
	
	
	/**
	 * Encrypt - Using RSA
	 * @param n          n (RSA)
	 * @param e          ku
	 * @param fileIn     name of plain-text file to encrypt
	 */
	protected static void Encrypt(BigInteger n, BigInteger e, String fileIn) {
		 
		// get key bit size
		int keySize = n.bitLength();     
		// get byte size, needs to be smaller than key size and in blocks of 8
		int messageSize = Math.min((keySize-1)/8,256);
		// determine byte size of cipher
		int cipherSize = 1 + (keySize-1)/8;           
		
		// -----------------------------------------------------
		// Im using files
		// -----------------------------------------------------
		try {
		     FileInputStream inFile = new FileInputStream(fileIn);
		     FileOutputStream fileOut = new FileOutputStream("enc.txt");
		     byte[] messageBlock = new byte[messageSize];
		     byte[] cipherBlock = new byte[cipherSize];
		     int blocks = 0;
		     int dataSize = inFile.read(messageBlock);
		     boolean didPad = false; 
		
		     // encrypt whole message
		     while (dataSize>0) {
		    	blocks++;
				
		    	// -----------------------------------------------------
				// Padding
				// -----------------------------------------------------
		    	
		    	
			    // message needs to be multiples of the block size, pad just in case
			    if (dataSize<messageSize) {
			    	// determine size of message (length)
			       int mbSize = messageBlock.length;
			       	// determine size we need to pad
				      int padding = mbSize - dataSize;
				     // get remainder to get size we will pad
				      int padSize = padding%mbSize;
				      for (int i=0; i<padding; i++) {  
				    	  // add the size to equal pad requirements
				          messageBlock[mbSize-i-1] = (byte) padSize;
				      }
			       didPad = true;
			    }
		    
			 // -----------------------------------------------------
			 // ENCRYPTION
			 // -----------------------------------------------------
			    
			    // turn text into big integer
			    BigInteger messageText = new BigInteger(1,messageBlock);
			    // THIS IS THE ENCRYPTION
			    BigInteger cipherText = messageText.modPow(e,n);
			    
			    //  Now we need to put cipher message together
			    //  Convert encrypted integers into byte blocks with a equal number of bytes for each integer. 
			    // put it back together
			    byte[] ctBytes = cipherText.toByteArray();
			    
			    // cipher block
			    int cbSize = cipherBlock.length;
			    // cipher text byte size
			    int cdSize = ctBytes.length;
			    int i = 0;
			    while (i<cdSize && i<cbSize) {
			    	cipherBlock[cbSize-i-1] = ctBytes[cdSize-i-1];
			        i++;
			    }
			    while (i<cbSize) {
			    	// pad "0x00", if the integer is small.
			    	cipherBlock[cbSize-i-1] = (byte)0x00;
			        i++;
			    }
			    fileOut.write(cipherBlock);
			    dataSize = inFile.read(messageBlock);
		 }
		     fileOut.close();
	         inFile.close();
	         //System.out.println("Encryption block count: "+blocks);
	      } catch (Exception ex) {
	         ex.printStackTrace();
	      }
	   }
	
	
	/**
	 * Decrypt - Using RSA
	 * @param nn       n (RSA)
	 * @param dd       private key
	 * @param input    name of file to decrypt
	 * @param output   name of file that is that decrypted version
	 */
	public static void Decrypt(String nn, String dd, String input, String output) {

		   String str = null;
		   BigInteger n = new BigInteger(nn);
		   BigInteger d = new BigInteger(dd);
		   
		    int keySize = n.bitLength();     
			// get byte size, needs to be smaller than key size and in blocks of 8
			int messageSize = Math.min((keySize-1)/8,256);
			// determine byte size of cipher
			int cipherSize = 1 + (keySize-1)/8;             
	      
	      try {
 	    FileInputStream inFile = new FileInputStream(input);
 	    FileOutputStream fileOut = new FileOutputStream(output);
 	    
	    	byte[] messageBlock = new byte[messageSize];
 	  	byte[] cipherBlock = new byte[cipherSize];
 	  	int blocks = 0;
	        int dataSize = 0;
	         while (inFile.read(cipherBlock)>0) {
	            blocks++;
	            // everything is big integer before we compile back to text
	            BigInteger cipherText = new BigInteger(1,cipherBlock);
	            BigInteger plainText = cipherText.modPow(d,n);
	            byte[] messageText = plainText.toByteArray();
	            int blockSize = messageBlock.length;
	  	      	int textSize = messageText.length;
	  	      	int i = 0;
	  	      	// assemble file back together
	  	      	while (i<textSize && i<blockSize) {
	  	    	  messageBlock[blockSize-i-1] = messageText[textSize-i-1];
	  	          i++;
	  	      	}
	  	      	while (i<blockSize) {
	  	    	  messageBlock[blockSize-i-1] = (byte)0x00;
	  	          i++;
	  	      	}
	  	      	
	            dataSize = messageSize;
	            if (inFile.available()==0) {
	      	      	int padValue = messageBlock[blockSize-1];
	      	      	dataSize = (blockSize-padValue)%blockSize;
	            }
	            if (dataSize>0) {
	            	// actual writing of plain text
	               fileOut.write(messageBlock,0,dataSize);
	            }
	         }
	         inFile.close();
	         
	      } catch (Exception ex) {
	         ex.printStackTrace();
	      }
	      
	     
	   }
	
	
	
	
	
	
	
	

}
