package be.suyo.toascrypt;

public class CryptException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    
    public CryptException() {
        super();
    }
    public CryptException(String s) {
        super(s);
    }
    public CryptException(Throwable t) {
        super(t);
    }
    public CryptException(String s, Throwable t) {
        super(s,t);
    }
}
