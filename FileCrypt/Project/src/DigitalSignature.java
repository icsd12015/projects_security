import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;


//H klasi gia tin psifiaki upografi an kai de prolava na ulopoihsw ton mixanismo akeraiotitas
public class DigitalSignature {
    Signature signature;
    byte[] signatureBytes;
    String signatureEncoded;
    
    public DigitalSignature(String text,PublicKey publicKey,PrivateKey privateKey){
        try {
            byte[] data = text.getBytes("UTF8");
            signature = Signature.getInstance("MD5WithRSA");
            signature.initSign(privateKey);
            signature.update(data);
            signatureBytes = signature.sign();
            
            signatureEncoded = Base64.getEncoder().encodeToString(signatureBytes);
            
            signature.initVerify(publicKey);
            signature.update(data);
        } catch (Exception ex) {
            Logger.getLogger(DigitalSignature.class.getName()).log(Level.SEVERE, null, ex);
        }



    }
    public boolean verify(){
        try {
            return signature.verify(signatureBytes);
        } catch (SignatureException ex) {}
        return false;
    }
}
