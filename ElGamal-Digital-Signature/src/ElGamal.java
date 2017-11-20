import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class ElGamal {

    private static final BigInteger PRIME_MODULUS = new BigInteger("127535493162319491367599324144113397151267257148437073602577007476663416682283880509178453980712280826088110844217588960715906052913674575697307662046615167011490493434401195847397477647858404441309473347516622650761427775164494413943726345063939069393839834502462904588970717436583818040772899540342776230691");
    private static final BigInteger GENERATOR = new BigInteger("48400272268446149001949240086817036655504892222066667076102118991277188776868539342358437315902355506279689976415512494001768854719270638359182186506891569799700611107926787284268168015589160654008081804779596215698189364060427211358575700634110443239682119451461713898704893457201278947928473195501316406632");
    private static final BigInteger PRIME_MODULUS_MINUS_ONE = PRIME_MODULUS.subtract(BigInteger.ONE);

    public static void main(String [] args) {
        if(args.length < 1){
            throw new IllegalArgumentException("Need file path");
        }

        byte [] file = fileToByteArray(args[0]);

        BigInteger secretKey = new BigInteger(PRIME_MODULUS.bitLength(), new Random());
        BigInteger publicKey = GENERATOR.modPow(secretKey, PRIME_MODULUS);

        BigInteger m = BigInteger.ZERO;
        try {
            BigInteger s = BigInteger.ZERO;
            BigInteger r = BigInteger.ZERO;
            while(s.equals(BigInteger.ZERO)) {

                //Choose a random value k with 0 < k < p-1 and gcd(k,p-1) = 1
                BigInteger k = new BigInteger(PRIME_MODULUS.bitLength() - 1, new SecureRandom());
                while(!isRelativelyPrime(k,PRIME_MODULUS_MINUS_ONE)){
                    k = new BigInteger(PRIME_MODULUS.bitLength() - 1, new SecureRandom());
                }

                //Compute r as r = gk (mod p)
                r = GENERATOR.modPow(k, PRIME_MODULUS);

                //Compute s as s = (H(m)-xr)k-1 (mod p-1)
                m = new BigInteger(MessageDigest.getInstance("SHA-256").digest(file)); //H(m)
                BigInteger xr = secretKey.multiply(r); //xr
                s = m.subtract(xr); //H(m)-xr
                s = s.multiply(modularInverse(k, PRIME_MODULUS_MINUS_ONE));
                s = s.mod(PRIME_MODULUS_MINUS_ONE);
                //If s=0 start over again
            }
            System.out.println("Public Key: " + publicKey.toString(16));
            System.out.println("Private Key: " + secretKey.toString(16));
            System.out.println("R: " + r.toString(16));
            System.out.println("S: " + s.toString(16));
            System.out.println("File: " + byteToHex(file));
            System.out.println("Hashed File: " + m.toString(16));

            if(verify(PRIME_MODULUS,GENERATOR,publicKey,r,s,file)){
                System.out.println("Verified!");
            }
            else{
                System.out.println("Failed to verify!");
            }

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: NoSuchAlogrithm found for digest");
        }


    }

    private static boolean verify(BigInteger p,BigInteger g, BigInteger y,BigInteger r,BigInteger s,byte [] m){

        //check that 0 < r < p and 0 < s < p-1
        if((1 != r.compareTo(BigInteger.ZERO))||(-1 != r.compareTo(p))||(1 != s.compareTo(BigInteger.ZERO))||(-1 != s.compareTo(p.subtract(BigInteger.ONE)))){
            return false;
        }
        // generate the 256-bit digest H(m)
        BigInteger hashedMessage;
        try {
            hashedMessage = new BigInteger(MessageDigest.getInstance("SHA-256").digest(m));
        }
        catch (NoSuchAlgorithmException e){
            return false;
        }
        //verify that gH(m) (mod p) = yrrs (mod p)
        BigInteger ghm = g.modPow(hashedMessage,p);
        BigInteger tmp1 = y.modPow(r, p);
        BigInteger tmp2 = r.modPow(s, p);
        BigInteger tmp = tmp1.multiply(tmp2);
        BigInteger yr_rs = tmp.mod(p);
        return ghm.equals(yr_rs);
    }

    //https://en.wikipedia.org/wiki/Euclidean_algorithm#Implementations
    private static boolean isRelativelyPrime(BigInteger a, BigInteger b) {
        BigInteger t;
        while(!b.equals(BigInteger.ZERO)){
            t = b;
            b = a.mod(b);
            a = t;
        }
        return a.equals(BigInteger.ONE);
    }

    //https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    //https://www.youtube.com/watch?v=hB34-GSDT3k
    private static BigInteger[] extendedEuclideanAlgorithm(BigInteger a, BigInteger b){
        BigInteger[] remainders = new BigInteger[3];
        if(b.equals(BigInteger.ZERO)){
            remainders[0] = a;
            remainders[1] = BigInteger.ONE;
            remainders[2] = BigInteger.ZERO;

            return remainders;
        }

        BigInteger x,y;
        remainders = extendedEuclideanAlgorithm(b, a.mod(b));
        x = remainders[1];
        y = remainders[2];
        remainders[1] = remainders[2];
        remainders[2] = x.subtract(y.multiply(a.divide(b)));
        return remainders;
    }


    //https://www.youtube.com/watch?v=fz1vxq5ts5I
    private static BigInteger modularInverse(BigInteger a, BigInteger b){
        BigInteger[] tmp = extendedEuclideanAlgorithm(a, b);
        if(!tmp[0].equals(BigInteger.ONE))
            throw new ArithmeticException(); //can't do anything if it's one
        if(tmp[1].compareTo(BigInteger.ZERO) > 0)
            return tmp[1];
        else
            return tmp[1].add(b);
    }

    private static byte[] fileToByteArray(String filePath) {
        File file = new File(filePath);
        byte[] fileArray = new byte[(int) file.length()];
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            fileInputStream.read(fileArray);
        } catch (FileNotFoundException e) {
            System.out.println("File Not Found.");
            e.printStackTrace();
        } catch (IOException e1) {
            System.out.println("Error Reading The File.");
            e1.printStackTrace();
        }
        return fileArray;
    }

    private static String byteToHex(byte[] array) {
        StringBuilder builder = new StringBuilder();
        for (byte b : array) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }
}
