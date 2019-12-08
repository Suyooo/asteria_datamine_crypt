package be.suyo.toascrypt.file;

import be.suyo.toascrypt.CryptException;

public class Decrypt extends Crypt {
    public Decrypt(byte[] header, String filename) {
        super(header, filename);
        
        for (int i = 0; i < 4; i++) {
            if (header[i] != md5hash[i+4]) {
                throw new CryptException("Header doesn't match");
            }
        }
    }
}
