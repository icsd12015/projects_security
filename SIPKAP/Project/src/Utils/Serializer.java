package Utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author icsd12015
 */
public class Serializer {

    public static byte[] serialize (Object obj) {
        try {
            try (ByteArrayOutputStream b = new ByteArrayOutputStream()) {
                try (ObjectOutputStream o = new ObjectOutputStream(b)) {
                    o.writeObject(obj);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                return b.toByteArray();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Object deserialize (byte[] bytes) {
        try {
            try (ByteArrayInputStream b = new ByteArrayInputStream(bytes)) {
                try (ObjectInputStream o = new ObjectInputStream(b)) {
                    return o.readObject();
                } catch (IOException | ClassNotFoundException ex) {
                    Logger.getLogger(Serializer.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return null;
    }

}
