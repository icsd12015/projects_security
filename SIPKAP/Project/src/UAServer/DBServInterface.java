package UAServer;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author icsd12015
 */
public interface DBServInterface extends Remote {

    public String getClientDigest (String username, byte[] nonce, byte[] c_nonce, String algorithm) throws RemoteException, NoSuchAlgorithmException;
}
