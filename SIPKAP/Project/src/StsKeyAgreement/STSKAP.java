package StsKeyAgreement;

import Security.*;
import Utils.ColorPrint;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author icsd12015 icsd11162
 */
public class STSKAP {

    public static enum Role {

        REFERRER,
        REFEREE,
    }

    private final Provider security_provider;

    private DHParameterSpec DHparams;
    private KeyPair keys;
    private KeyAgreement keyagree;

    private SecretKey commonKey;

    private KeyPair RSAkeys;
    private X509Certificate cert;

    private byte[] signature;

    public STSKAP (Provider prov) {
        Security.setProperty("crypto.policy", "unlimited");
        this.security_provider = prov;
    }

    public boolean doKeyAgreement (Role role, ObjectInputStream in, ObjectOutputStream out) {
        try {
            if (role == Role.REFERRER) {

                DHPublicKey sDHpub = (DHPublicKey) in.readObject();

                ColorPrint.print("Received Proxy's DiffieHellman Public Key", ColorPrint.ANSI_YELLOW);

                initialize(sDHpub.getParams());

                ColorPrint.print("Proxy's DiffieHellman Key Agreement initialized", ColorPrint.ANSI_YELLOW);

                proceed(sDHpub);
                initAuth(sDHpub);

                ColorPrint.print("Proxy generated Common Secret Key and Signature", ColorPrint.ANSI_YELLOW);

                DHPublicKey pubkey = getDHPublicKey();
                signature = getSignature();
                byte[] encSignature = EncryptionTool.Encrypt(signature, getCommonKey(), "AES", false, security_provider);
                String sign = Base64.toBase64String(encSignature);

                out.writeObject(pubkey);
                out.flush();
                out.writeUTF(sign);
                out.flush();

                ColorPrint.print("Proxy sent Common Secret Key and Signature to Proxy", ColorPrint.ANSI_YELLOW);

                sDHpub = (DHPublicKey) in.readObject();
                byte[] sEncSignature = Base64.decode(in.readUTF());

                ColorPrint.print("Proxy received Client's DiffieHellman Public Key and Signature", ColorPrint.ANSI_YELLOW);

                proceed(sDHpub);
                initAuth(sDHpub);

                ColorPrint.print("Proxy generated Common Secret Key and Signature", ColorPrint.ANSI_YELLOW);

                byte[] sSignature = EncryptionTool.Decrypt(sEncSignature, getCommonKey(), "AES", false, security_provider);

                if (authenticate(sDHpub, sSignature)) {
                    ColorPrint.print("Proxy's Protocol Session Authenticated", ColorPrint.ANSI_YELLOW);

                    byte[] OK = EncryptionTool.Encrypt("OK".getBytes(), getCommonKey(), "AES/CBC/PKCS5Padding", true, security_provider);

                    out.writeUTF(Base64.toBase64String(OK));
                    out.flush();

                    String m = in.readUTF();

                    byte[] Dm = EncryptionTool.Decrypt(Base64.decode(m), getCommonKey(), "AES/CBC/PKCS5Padding", true, security_provider);

                    if (new String(Dm).equals("OK")) {
                        ColorPrint.print("Proxy's Station-to-Station Key Agreement Finished", ColorPrint.ANSI_YELLOW);
                        return true;
                    }
                }
            }

            if (role == Role.REFEREE) {

                initialize(STSKAP.getDHparamsRFC());

                ColorPrint.print("Client's DiffieHellman Key Agreement initialized", ColorPrint.ANSI_YELLOW);

                DHPublicKey pubkey = getDHPublicKey();
                out.writeObject(pubkey);
                out.flush();

                ColorPrint.print("Client sent DiffieHellman Public Key to Client", ColorPrint.ANSI_YELLOW);

                DHPublicKey cDHpub = (DHPublicKey) in.readObject();
                byte[] cEncSignature = Base64.decode(in.readUTF());

                ColorPrint.print("Client received Client's DiffieHellman Public Key and Signature", ColorPrint.ANSI_YELLOW);

                proceed(cDHpub);
                initAuth(cDHpub);

                ColorPrint.print("Client generated Common Secret Key and Signature", ColorPrint.ANSI_YELLOW);

                byte[] cSignature = EncryptionTool.Decrypt(cEncSignature, getCommonKey(), "AES", false, security_provider);

                if (authenticate(cDHpub, cSignature)) {

                    ColorPrint.print("Client's Protocol Session Authenticated", ColorPrint.ANSI_YELLOW);

                    signature = getSignature();
                    byte[] encSignature = EncryptionTool.Encrypt(signature, getCommonKey(), "AES", false, security_provider);
                    String sign = Base64.toBase64String(encSignature);

                    out.writeObject(pubkey);
                    out.flush();
                    out.writeUTF(sign);
                    out.flush();

                    ColorPrint.print("Client sent Common Secret Key and Signature to Client", ColorPrint.ANSI_YELLOW);

                    String m = in.readUTF();

                    byte[] Dm = EncryptionTool.Decrypt(Base64.decode(m), getCommonKey(), "AES/CBC/PKCS5Padding", true, security_provider);

                    if (new String(Dm).equals("OK")) {
                        byte[] OK = EncryptionTool.Encrypt("OK".getBytes(), getCommonKey(), "AES/CBC/PKCS5Padding", true, security_provider);
                        out.writeUTF(Base64.toBase64String(OK));
                        out.flush();
                        ColorPrint.print("Client's Station-to-Station Key Agreement Finished", ColorPrint.ANSI_YELLOW);
                        return true;
                    }
                }
            }

        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException | NoSuchProviderException ex) {
            ex.printStackTrace();
        }
        return false;
    }

    public void initialize (DHParameterSpec params) {
        this.DHparams = params;
        try {
            this.keys = KeyTool.generateKeyPair("DiffieHellman", this.DHparams, security_provider);
            keyagree = KeyAgreement.getInstance("DiffieHellman", new BouncyCastleProvider());
            keyagree.init(keys.getPrivate());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException ex) {
            ex.printStackTrace();
        }
    }

    public void proceed (PublicKey key) {
        try {
            keyagree.doPhase(key, true);
            byte[] k = keyagree.generateSecret();
            this.commonKey = KeyTool.constructKey("AES", 256, k);
        } catch (InvalidKeyException | IllegalStateException ex) {
            ex.printStackTrace();
        }
    }

    public void initAuth (PublicKey key) {
        try {
            this.RSAkeys = KeyTool.generateKeyPair("RSA", 2048, security_provider);
            PKCS10CertificationRequest csr = CertTool.generateRequest("Bob", RSAkeys.getPublic(), DHparams, CertTool.getCAcert(), CertTool.getCAprivateKey(), security_provider);
            this.cert = CertTool.getCertificate(csr, CertTool.getCAcert(), CertTool.getCAprivateKey(), security_provider);
            byte[] DHPubKeysBytes = concatBytes(keys.getPublic().getEncoded(), key.getEncoded());
            signature = SignatureTool.sign(DHPubKeysBytes, RSAkeys.getPrivate(), cert, CertTool.getCAcert(), security_provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException | OperatorCreationException | KeyStoreException | CertificateException | UnrecoverableKeyException |
                 InvalidKeySpecException | SignatureException | CMSException | InvalidKeyException ex) {
            ex.printStackTrace();
        }
    }

    public boolean authenticate (PublicKey key, byte[] signature) {
        try {
            X509Certificate cert = SignatureTool.getCertificate(signature, security_provider);
            byte[] DHPubKeysBytes = concatBytes(key.getEncoded(), keys.getPublic().getEncoded());
            boolean checkSig = SignatureTool.verify(DHPubKeysBytes, signature, security_provider);

            String bobG = CertTool.getExtensionValue(cert, CertTool.OID_P);
            String bobP = CertTool.getExtensionValue(cert, CertTool.OID_G);
            boolean checkParams = bobG.equals(DHparams.getG().toString()) && bobP.equals(DHparams.getP().toString());

            return checkSig && checkParams;
        } catch (CMSException | CertificateException | OperatorCreationException | IOException ex) {
            ex.printStackTrace();
        }
        return false;
    }

    public DHPublicKey getDHPublicKey () {
        return (DHPublicKey) this.keys.getPublic();
    }

    public SecretKey getCommonKey () {
        return this.commonKey;
    }

    public byte[] getSignature () {
        return signature;
    }

    public byte[] concatBytes (byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public static DHParameterSpec getDHparamsRFC () {
        //https://tools.ietf.org/html/rfc3526
        BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
        BigInteger G = BigInteger.valueOf(2);
        int L = 2047;

        return new DHParameterSpec(P, G, L);
    }
}
