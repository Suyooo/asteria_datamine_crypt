package be.suyo.toascrypt.network;

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import be.suyo.toascrypt.CryptException;

public class NetworkCrypt {
    final static String KEY = "HJfxRsgQPd4wXn2l";

    public static void main(String[] args) {
        try {
            if (args.length < 3 || !(args[0].equals("d") || args[0].equals("e"))) {
                System.err.println("Usage: Main [mode] [input file] [output file]");
                System.err.println("Mode is \"d\" for decryption, \"e\" for encryption");
                System.err.println("Specify input/output as \".\" to use stdin/stdout");
                System.exit(1);
            }
            
            byte[] in;
            if (args[1].equals(".")) {
                Scanner input = new Scanner(System.in);
                in = input.nextLine().getBytes();
                input.close();
            } else in = Files.readAllBytes(Paths.get(args[1]));
            
            byte[] result;
            if (args[0].equals("d")) {
                result = decrypt(in);
            } else {
                result = encrypt(in);
            }
            String out = new String(result);

            if (args[2].equals(".")) System.out.println(out);
            else {
                try (PrintWriter outfile = new PrintWriter(args[2])) {
                    outfile.write(out);                        
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static byte[] decrypt(byte[] data) {
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(data);
            byte[] iv =
                Arrays.copyOfRange(decoded, decoded.length - 24, decoded.length - 8);
            decoded = Arrays.copyOfRange(decoded, 3, decoded.length - 29);
    
            SecretKeySpec sks = new SecretKeySpec(KEY.getBytes(), "AES");
            IvParameterSpec ips = new IvParameterSpec(iv);
            Cipher c;
            c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, sks, ips);
            return c.doFinal(decoded);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                        InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptException(e);
        }
    }
    
    public static byte[] encrypt(byte[] data) {
        return encrypt(data, new byte[16]);
    }
    
    public static byte[] encrypt(byte[] data, byte[] iv) {
        try {
            SecretKeySpec sks2 = new SecretKeySpec(KEY.getBytes(), "AES");
            IvParameterSpec ips2 = new IvParameterSpec(iv);
            Cipher c2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c2.init(Cipher.ENCRYPT_MODE, sks2, ips2);
            byte[] encrypted = c2.doFinal(data);
            
            byte[] completedata = new byte[3 + encrypted.length + 5 + iv.length + 8];
            System.arraycopy(encrypted, 0, completedata, 3, encrypted.length);
            System.arraycopy(iv, 0, completedata, completedata.length - 24, iv.length);
            
            return java.util.Base64.getEncoder().encode(completedata);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                        InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptException(e);
        }
    }
}