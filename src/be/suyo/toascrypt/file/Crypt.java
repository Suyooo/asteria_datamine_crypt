package be.suyo.toascrypt.file;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import be.suyo.toascrypt.CryptException;

// Based on HonokaMiku
public abstract class Crypt {
    public static final byte[] prefix = "dpQwjV9rp3g5".getBytes();
    
    // Key used at pos 0. Used when the decrypter needs to jump to specific-position
    int init_key;
    // Current key at `pos`
    int update_key;
    // Variable to track current position. Needed to allow jump to specific-position
    long pos;
    // Values to use when XOR-ing bytes
    int xor_key;
    
    byte[] md5hash;
    
    public Crypt(byte[] header, String filename) {
        MessageDigest md5;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptException("MD5 is not available? This should never happen", e);
        }
        byte[] basename = getBasename(filename).getBytes();

        md5.update(prefix);
        md5.update(basename);
        md5hash = md5.digest();
        
        init_key = ((md5hash[0] & 0x7F) << 24) | ((md5hash[1] & 0xFF) << 16) | ((md5hash[2] & 0xFF) << 8) | (md5hash[3] & 0xFF);
        update_key = init_key;
        xor_key = ((init_key>>>23) & 0xFF) | ((init_key >>> 7) & 0xFF00);
        pos = 0;
    }
    
    private void update() {
        int a,b,c,d;

        a = update_key >>> 16;
        b = ((a * 0x41A70000) & 0x7FFFFFFF) + (update_key & 0xFFFF) * 0x41A7;
        c = (a * 0x41A7) >>> 15;
        d = c + b - 0x7FFFFFFF;
        b = (b == 0x7FFFFFFF || (b & 0x80000000) != 0) ? d : (b + c);

        update_key = b;
        xor_key = ((b >>> 23) & 0xFF) | ((b >>> 7) & 0xFF00);
    }

    public void decrypt_block(byte[] src) {
        int len = src.length;
        if (len == 0) return;
        
        int buffer_pos = 0;
        
        if(pos%2 == 1)
        {
            src[0] ^= xor_key >> 8;
            buffer_pos++;
            len--;
            pos++;

            update();
        }
        
        for (int decrypt_size = len / 2; decrypt_size != 0; decrypt_size--, buffer_pos += 2)
        {
            src[buffer_pos] ^= xor_key;
            src[buffer_pos + 1] ^= xor_key >> 8;

            update();
        }
        
        if ((len & 0xFFFFFFFE) != len)
            src[buffer_pos] ^= xor_key;
        
        pos += len;
    }
    
    public byte[] decrypt_block_to_new_array(byte[] src) {
        byte[] res = Arrays.copyOf(src, src.length);
        decrypt_block(res);
        return res;
    }
    
    public void goto_offset(long offset) {
        long loop_times;
        boolean reset_dctx = false;
        
        if(offset < 0) throw new CryptException("Position is negative.");

        if (offset > pos)
            loop_times = offset - pos;
        else if (offset == pos) return;
        else
        {
            loop_times = offset;
            reset_dctx = true;
        }

        if (reset_dctx)
        {
            update_key = init_key;
            xor_key = ((init_key >>> 23) & 0xFF) | ((init_key >>> 7) & 0xFF00);
        }
        
        if (pos % 2 == 1 && !reset_dctx)
        {
            loop_times--;
            update();
        }
        
        loop_times /= 2;
        
        for(; loop_times != 0; loop_times--)
            update();

        pos = offset;
    }
    
    public void goto_offset_relative(int offset) {
        if (offset == 0) return;
        long x = pos + offset;
        goto_offset(x);
    }
    
    public String getBasename(String filename) {
        int pos = filename.length() - 1;
        while (filename.charAt(pos) != '/' && filename.charAt(pos) != '\\' && pos > 0) {
            pos--;
        }
        if (pos == 0) return filename;
        else return filename.substring(pos + 1);
    }
}
