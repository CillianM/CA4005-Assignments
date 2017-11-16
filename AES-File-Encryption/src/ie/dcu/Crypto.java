package ie.dcu;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.Scanner;

public class Crypto {

    private static final int HASH_ITERATIONS = 200;
    private static final int KEY_LENGTH = 256;
    private static Random random = new SecureRandom(); //https://crackstation.net/hashing-security.htm
    private static final BigInteger EXPONENT = new BigInteger("65537");
    private static final BigInteger PUBLIC_MODULO = new BigInteger("c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9", 16);
    private static final int BYTE_VALUE = 16;
    private static String ENCRYPTED_FILE_NAME = "EncryptedFile";
    private static String DECRYPTED_FILE_NAME = "DecryptedFile";
    private static final String HASH_METHOD = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_TYPE = "AES/CBC/NoPadding";
    private static final String KEY_SPEC_TYPE = "AES";


    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter Password: ");
        String password = scan.next();
        String fileExtension = args[0].substring(args[0].lastIndexOf("."));
        ENCRYPTED_FILE_NAME += fileExtension;
        DECRYPTED_FILE_NAME += fileExtension;
        byte[] salt = getSalt();
        byte[] hashedPassword = hashPassword(password, salt);
        String val = modularExponentiation(password.getBytes());
        byte[] initVector = encrypt(hashedPassword, args[0]);
        decrypt(hashedPassword, initVector, ENCRYPTED_FILE_NAME);

        System.out.println("Plaintext Password: " + password);
        System.out.println("Salt: " + byteToHex(salt));
        System.out.println("Hashed Password: " + byteToHex(hashedPassword));
        System.out.println("Init Vector: " + byteToHex(initVector));
        System.out.println("RSA Encrypted Password: " + val);

    }

    private static String byteToHex(byte[] array) {
        StringBuilder builder = new StringBuilder();
        for (byte b : array) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    private static byte[] getSalt() {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private static byte[] hashPasswordHmac(char[] password, byte[] salt) {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, HASH_ITERATIONS, KEY_LENGTH);
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(HASH_METHOD);
            return secretKeyFactory.generateSecret(pbeKeySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError("Error while hashing: " + e.getMessage(), e);
        }
    }

    private static byte[] hashPassword(String password, byte[] salt) {
        byte[] saltedPassword = concatenateArrays(password.getBytes(), salt);
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(saltedPassword);
            for (int i = 0; i < HASH_ITERATIONS - 1; i++) {
                hash = messageDigest.digest(hash);
            }
            return hash;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("Error while hashing: " + e.getMessage(), e);
        }
    }

    private static byte[] concatenateArrays(byte[] a, byte[] b) {
        byte[] concatenatedArray = new byte[a.length + b.length];
        System.arraycopy(a, 0, concatenatedArray, 0, a.length);
        System.arraycopy(b, 0, concatenatedArray, a.length, b.length);
        return concatenatedArray;
    }

    private static byte[] encrypt(byte[] key, String filePath) {
        try {
            byte[] fileBytes = fileToPaddedByteArray(filePath);
            byte[] initVector = getSalt();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, KEY_SPEC_TYPE);

            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] encryptedBytes = cipher.doFinal(fileBytes);
            writeByteToFile(ENCRYPTED_FILE_NAME, encryptedBytes);
            return initVector;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private static void decrypt(byte[] key, byte[] initVector, String filePath) {
        try {
            byte[] fileBytes = fileToByteArray(filePath);
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec skeySpec = new SecretKeySpec(key, KEY_SPEC_TYPE);

            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] decryptedBytes = cipher.doFinal(fileBytes);
            writeByteToFile(DECRYPTED_FILE_NAME, decryptedBytes);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static String modularExponentiation(byte[] password) {
        //Right to left variant for calculating y = a^x (mod p): p ^ e (mod N)

        BigInteger value = new BigInteger(password);
        int length = EXPONENT.toByteArray().length * 8;

        BigInteger y = new BigInteger("1");
        for (int j = 0; j < length; j++) {
            if (isBitSet(EXPONENT.intValue(), j)) {
                y = (y.multiply(value));
                y = y.mod(PUBLIC_MODULO);
            }
            value = (value.multiply(value));
            value = value.mod(PUBLIC_MODULO);
        }
        return y.toString(16);
    }

    private static boolean isBitSet(int b, int position) {
        return ((b >> position) & 1) == 1;
    }

    private static void writeByteToFile(String filename, byte[] bytes) {
        File file = new File(filename);
        try {
            file.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            for (byte fileByte : bytes) {
                fileOutputStream.write(fileByte);
            }
        } catch (FileNotFoundException e) {
            System.out.println("File Not Found.");
            e.printStackTrace();
        } catch (IOException e1) {
            System.out.println("Error Reading The File.");
            e1.printStackTrace();
        }

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

    private static byte[] fileToPaddedByteArray(String filePath) {
        byte[] fileArray = fileToByteArray(filePath);
        if (fileArray.length % BYTE_VALUE == 0) {
            byte[] padding = new byte[BYTE_VALUE];
            padding[0] |= 1;
            return concatenateArrays(fileArray, padding);
        } else {
            return padArray(fileArray); //set the additional block as the padded array
        }
    }

    private static byte[] padArray(byte[] bytes) {
        //find the position at the end where to pad
        int overflowPosition = bytes.length % BYTE_VALUE;
        int remainder = BYTE_VALUE - overflowPosition;
        //create the necessary padding to make another 16 byte block
        byte[] padding = new byte[remainder];
        padding[0] |= 1; //set the padding byte to 1
        byte[] paddedArray = new byte[bytes.length + padding.length];
        System.arraycopy(bytes, 0, paddedArray, 0, bytes.length);
        System.arraycopy(padding, 0, paddedArray, bytes.length, padding.length);
        return paddedArray;


    }
}
