package be.suyo.toascrypt.file;

public class Encrypt extends Crypt {
    public Encrypt(byte[] header, String filename) {
        super(header, filename);

        System.arraycopy(md5hash, 4, header, 0, 4);
    }
}
