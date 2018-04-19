import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PBKDF2 {
    private SecretKey DK;
    private SecretKey DK256;
    private final String P;
    private final String S;
    private final int c;
    private final int dkLen;

    public PBKDF2(String P, String S, int c, int dkLen){
        this.P = P;
        this.S = S;
        this.c = c;
        this.dkLen = dkLen;
        derive();
    }
    public SecretKey getDK(){
        return DK;
    }
    public SecretKey getDK256(){
        return DK;
    }
    //H methodos antlisis kleidiwn me ton algorithmo RFC2898
    //Dimiourgw duo kleidia wste to ena na xrisimopoihthei sto authentication tou xristi me megethos 32
    //Enw to allo gia ti kwdikopoihsh twn arxeiwn me AES256 (me megethos 256)
    private SecretKey derive(){
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec ks = new PBEKeySpec(P.toCharArray(), S.getBytes("UTF-8"), c, 256 + dkLen * 8);
            
            SecretKey fullKey = f.generateSecret(ks);
            byte[] fullKeyBytes = fullKey.getEncoded();
            
            DK = new SecretKeySpec(Arrays.copyOfRange(fullKeyBytes, 0, dkLen), "AES");
            DK256 = new SecretKeySpec(Arrays.copyOfRange(fullKeyBytes, dkLen, fullKeyBytes.length), "AES");
            return f.generateSecret(ks);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeySpecException ex) {
            Logger.getLogger(PBKDF2.class.getName()).log(Level.SEVERE, null, ex);
        }
      return null;  
    }
}
