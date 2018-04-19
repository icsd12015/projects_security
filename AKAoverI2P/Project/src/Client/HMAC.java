package Client;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class HMAC {

    //Αυτη η μεθοδος κατακερματιζει ενα αλφαριθμητικο με HMAC και ενα αλγοριθμο κατακερματισμου
    public static String Hash(String value, byte[] key, String hashAlgorithm) {

        try {
            SecretKeySpec signingKey = new SecretKeySpec(key, "Hmac" + hashAlgorithm.replaceAll("-", ""));

            Mac mac = Mac.getInstance("Hmac" + hashAlgorithm.replaceAll("-", ""));
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(value.getBytes());

            byte[] hexBytes = new Hex().encode(rawHmac);

            return new String(hexBytes, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
