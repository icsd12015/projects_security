
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.logging.Level;
import java.util.logging.Logger;
import research.HashTextTest;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author GamateKID
 */
public class SHA1 {
    String encoded;
    
    public void sha1(String input) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            byte[] result = sha1.digest(input.getBytes());
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < result.length; i++) {
                sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
            }
            
            encoded = sb.toString();
        } catch (Exception ex) {
            Logger.getLogger(HashTextTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void sha1(File file){
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            FileInputStream fis = new FileInputStream(file);
             byte[] data = new byte[1024];
            int read = 0; 
            while ((read = fis.read(data)) != -1) {
                sha1.update(data, 0, read);
            };
            byte[] hashBytes = sha1.digest();

            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < hashBytes.length; i++) {
              sb.append(Integer.toString((hashBytes[i] & 0xff) + 0x100, 16).substring(1));
            }

            encoded = sb.toString();
        } catch (Exception ex) {
            Logger.getLogger(HashTextTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
