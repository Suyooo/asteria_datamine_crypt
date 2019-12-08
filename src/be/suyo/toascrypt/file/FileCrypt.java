package be.suyo.toascrypt.file;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class FileCrypt {
    public static void main(String[] args) {
        try {
            if (args.length < 3 || !(args[0].equals("d") || args[0].equals("e"))) {
                System.err.println("Usage: Main [mode] [input file] [output file] [override filename]");
                System.err.println("Mode is \"d\" for decryption, \"e\" for encryption");
                System.err.println("Specify the optional override to use that filename for de-/encryption instead of the input filename");
                System.exit(1);
            }
            
            byte[] in = Files.readAllBytes(Paths.get(args[1]));
            
            byte[] result;
            if (args[0].equals("d")) {
                if (args.length > 3) result = decrypt(in, args[3]);
                else result = decrypt(in, args[1]);
            } else {
                if (args.length > 3) result = encrypt(in, args[3]);
                else result = encrypt(in, args[1]);
            }

            try (FileOutputStream outfile = new FileOutputStream(args[2])) {
                outfile.write(result);                        
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static byte[] decrypt(byte[] data, String filename) {
        Crypt c = new Decrypt(data, filename);
        return c.decrypt_block_to_new_array(Arrays.copyOfRange(data, 4, data.length));
    }
    
    public static byte[] encrypt(byte[] data, String filename) {
        byte[] result = new byte[4 + data.length];
        Crypt c = new Encrypt(result, filename);
        System.arraycopy(c.decrypt_block_to_new_array(data), 0, result, 4, data.length);
        return result;
    }
}