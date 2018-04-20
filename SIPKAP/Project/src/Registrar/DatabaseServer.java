package Registrar;

import Security.Digest;
import java.io.IOException;
import java.io.Serializable;
import UAServer.DBServInterface;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import org.bouncycastle.util.encoders.Base64;
/**
 *
 * @author icsd12015
 */
public class DatabaseServer extends UnicastRemoteObject implements DBServInterface, Serializable {

    private Connection DBconnection;
    private Statement statement;

    private String name;
    private int port;

    //Prosomoiwsi enos Registar (aplws einai enas RMI Server opou diavazei ta passwords apo ena arxeio vasis kai epistrefei ti sunopsi tous)
    public DatabaseServer (String name, int port, String dbfile) throws RemoteException {
        try {
            this.name = name;
            this.port = port;

            Class.forName("org.sqlite.JDBC");
            DBconnection = DriverManager.getConnection("jdbc:sqlite:" + dbfile);
            statement = DBconnection.createStatement();

            try {
                LocateRegistry.createRegistry(port);
                Runtime.getRuntime().exec("rmiregistry " + port);
            } catch (java.rmi.server.ExportException e) {

            }

            Naming.rebind("//localhost:" + port + "/" + name, this);

        } catch (IOException | ClassNotFoundException | SQLException ex) {
            System.err.println(ex.toString());
        }
    }

    @Override
    //Vriskei ton kwiko vasi tou username apo ti vasi kai upologizei vasi twn parametrwn salts kai algorithmou kai epistrefei ti sunopsi
    public String getClientDigest (String username, byte[] nonce, byte[] c_nonce, String algorithm) throws RemoteException, NoSuchAlgorithmException {

        try {
            ResultSet records;
            String query = "SELECT * from Clients WHERE username = '" + username + "' ";

            records = statement.executeQuery(query);

            if (records != null) {
                while (records.next()) {
                    byte[] c_pass = records.getString("password").getBytes();
                    return Base64.toBase64String(Digest.HashWithSalt(c_pass, nonce, c_nonce, algorithm));
                }
            }
            return null;
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public String getURL () {
        return "//localhost:" + this.port + "/" + this.name;
    }
}
