package Server;

import java.awt.Dimension;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import net.i2p.I2PException;
import net.i2p.client.I2PSession;
import net.i2p.client.streaming.I2PServerSocket;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import net.i2p.util.I2PThread;
import sun.misc.BASE64Decoder;

class I2PServer {

    private final static String myPublicKeyEncoded
            = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnkIJsUgTDDoGvP04Rfzs\n"
            + "4CuxxuDo6CsC6lb9YwZk8V8Y2hWw1jw45hynCWECc/27qR664kmDTrNf4NqyvEah\n"
            + "Na4eKugHtyoaoR0Yt6s4zmNQ0yBIdIvvGU4rBxCHMTcHjiiihwWy0Mr3awVIzFrS\n"
            + "srlFtfa1roo57bx22JtL40z+3Hn1Q1bEtokkqD8cDRGnYfo5OGZFdCeE26651Sh1\n"
            + "cCLDMF9fEaP0iPqles59hK8ySgWGaeK+pWeZofwqa5I2ZZBA/DayeD1472lCVxb7\n"
            + "6OtkF3iTj+acIScS/sJwPpPxUDxR03qHrDal+fZMVX5OLlxDZMjd8rxHAY73FOH6\n"
            + "awIDAQAB";

    private final static String myPrivateKeyEncoded
            = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCeQgmxSBMMOga8\n"
            + "/ThF/OzgK7HG4OjoKwLqVv1jBmTxXxjaFbDWPDjmHKcJYQJz/bupHrriSYNOs1/g\n"
            + "2rK8RqE1rh4q6Ae3KhqhHRi3qzjOY1DTIEh0i+8ZTisHEIcxNweOKKKHBbLQyvdr\n"
            + "BUjMWtKyuUW19rWuijntvHbYm0vjTP7cefVDVsS2iSSoPxwNEadh+jk4ZkV0J4Tb\n"
            + "rrnVKHVwIsMwX18Ro/SI+qV6zn2ErzJKBYZp4r6lZ5mh/CprkjZlkED8NrJ4PXjv\n"
            + "aUJXFvvo62QXeJOP5pwhJxL+wnA+k/FQPFHTeoesNqX59kxVfk4uXENkyN3yvEcB\n"
            + "jvcU4fprAgMBAAECggEAYiRN4nTx6wkpGJZoCW8absJqEw1zIldaDX040eorO0xg\n"
            + "Gw6Mha7/EiT+qWBRpyDY+b4m4yH3nhy6/rRhV0TtwF5kMvOFpV8k+HkU1QIHzmXk\n"
            + "v6krhasp8aV6JX1oeWrI8q3cbKNqCvVzjhjO1nwUYeVnh7qhXMY3umi/wwA7hY9G\n"
            + "Z81D6v03snQJk8V9rXK4EzCmQd0W33kn9P441eOtff8hrZjO88rD9EtC6YsZu0ZH\n"
            + "CSiI1VppLFiMpcwwFaeUVk4M3zjgUkz0FmnnT5QdtLL4jelX7uVumthpN8wn0uzA\n"
            + "KngBUXCMqFYCzv/KciGih3bjCwuxHuW0lH2fTFcUYQKBgQDMi9mdxlbY7ccmEeCW\n"
            + "mK8dGI4bZKC2AFd7esBcgFBTGGobs1dYLOjeoy9uU1fdDr52BTsKYEncaKUy7SuT\n"
            + "GIy0XRt77EE8YOatR2qF6O4eER2AHtIibnxXn/M5ZqjMAYy8Uya1I7qUY4DeTo9u\n"
            + "g48aYZgvZIwxs5JTsnFfljD4mQKBgQDGEVy7KRdWBgkCFANUSsWZh912YvZlvM3c\n"
            + "XaEdrIwFqNWrRpfaRK1uXYc+INY8ccICGhZMVI8UTxDUMQ/Lh9Vo2cqakxQQcdVp\n"
            + "436bAvfw8t9n+mbjEEYDpkJGKSSEDonjxoWyMckB7gBtZl/qfnK+lT0NOUZ11UYs\n"
            + "PL8o8wrZowKBgQCTAL85QN4RsXG6zoZWNQ1FH+yhi0RlCQHWYHX3BNC1p4o6tj1D\n"
            + "xaLmvujLpWI0IPCI6WFxJ5ptqVdwrjru0GnvBitGeJi5x/qA9h58dtcLDMni1kO3\n"
            + "Myhx4SZwTnNpioOWpTvgWvkwxAJNwrAagLpL/2/cP6rx3ViAhnIsfEhdoQKBgQCm\n"
            + "Yf1g56LHy6gTi9ZEH8+gKka6ZWWQjyrrW+e1MrYpJuvexh1X6Gs8E+tBIHp3KiSM\n"
            + "eXeTxVCwAb8kUNZw5fk67AFLGhQ3wDhDjCxVcQfw60UKZom5Ynk+JZL0tykKmd/x\n"
            + "bFnxF+s/6LuJKv+Vz4T6Xgl8K0nqQC+Dh8AZWRkbOwKBgCu/E5bMhqX2e4uiwsBG\n"
            + "bhl9Q+rCHKA2T3O2eqvSfeBhIG52sf0tatcBNcsJUVMSn1tP5WBQ0tDSuAE5CRXC\n"
            + "AR9eQ3kteaIxOuPwbqP5lZK6OBlnM5taBcMEiMyoCELqgN1uj4PUmshzkrwhESb2\n"
            + "IaInPakgBTS0gNeZvSZ9Yis/";

    public final static String CertificateEncoded
            = "MIIDkTCCAnmgAwIBAgIJAO8NXBLTTnSMMA0GCSqGSIb3DQEBBQUAMDkxJjAkBgNV\n"
            + "BAoUHWljc2QxMTE2Ml9pY3NkMTIwMTVfaWNzZDExMTIyMQ8wDQYDVQQDEwZOZXRT\n"
            + "ZWMwHhcNMTYxMDI5MjAxMzU4WhcNMTcxMDI5MjAxMzU4WjA5MSYwJAYDVQQKFB1p\n"
            + "Y3NkMTExNjJfaWNzZDEyMDE1X2ljc2QxMTEyMjEPMA0GA1UEAxMGTmV0U2VjMIIB\n"
            + "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnkIJsUgTDDoGvP04Rfzs4Cux\n"
            + "xuDo6CsC6lb9YwZk8V8Y2hWw1jw45hynCWECc/27qR664kmDTrNf4NqyvEahNa4e\n"
            + "KugHtyoaoR0Yt6s4zmNQ0yBIdIvvGU4rBxCHMTcHjiiihwWy0Mr3awVIzFrSsrlF\n"
            + "tfa1roo57bx22JtL40z+3Hn1Q1bEtokkqD8cDRGnYfo5OGZFdCeE26651Sh1cCLD\n"
            + "MF9fEaP0iPqles59hK8ySgWGaeK+pWeZofwqa5I2ZZBA/DayeD1472lCVxb76Otk\n"
            + "F3iTj+acIScS/sJwPpPxUDxR03qHrDal+fZMVX5OLlxDZMjd8rxHAY73FOH6awID\n"
            + "AQABo4GbMIGYMB0GA1UdDgQWBBQSyhTame3GZq6aFhun9aZNzgxBHjBpBgNVHSME\n"
            + "YjBggBQSyhTame3GZq6aFhun9aZNzgxBHqE9pDswOTEmMCQGA1UEChQdaWNzZDEx\n"
            + "MTYyX2ljc2QxMjAxNV9pY3NkMTExMjIxDzANBgNVBAMTBk5ldFNlY4IJAO8NXBLT\n"
            + "TnSMMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBACS+nR3AhZiXgtyp\n"
            + "B20/GwxdevMFceWQFZz+SHSUwdunlH7APVMI0z5PqUGMub3A26HKiDgdWb4XfytB\n"
            + "hkTn3JSso1+TMVKXOglhMLi+mAV4Bxio4S8RTK/K25+UO58N2+FAnzSDuOWvCTCx\n"
            + "likLyZtk1wq63RfYM0co8Q3l9eNAo5KDOBqI5Sm/+ApzYs1Jm/zQr309uVFJGSQi\n"
            + "8VDbLKPhbuSLek7MJP72R8VLBtV9d6/FsoCiSl2hjsjf3p2Mi3gRz3RPwfnnyKDM\n"
            + "sO0x6zu3ljJG0fS0CbMcLJtJiJPq53F0Ve4JrUrvGmP47Ll2c5VvKlNk5KTCbof8\n"
            + "3Jtr928=";

    //Με σειρα προτιμησης
    private final static ArrayList<String> SymmetricAlgorithmsSupported = new ArrayList() {
        {
            add("Twofish");
            add("Blowfish");
            add("AES");
        }
    };
    private final static ArrayList<String> HashAlgorithsSupported = new ArrayList() {
        {
            add("Whirlpool");
            add("SHA-512");
            add("SHA-384");
            add("SHA-256");
            add("SHA-224");
        }
    };
    public static PublicKey myPublicKey;
    public static PrivateKey myPrivateKey;

    private I2PSocket currSock;
    private I2PSocketManager manager;
    private I2PServerSocket serverSocket;
    private I2PSession session;
    private String dest;
    private JTextArea log;
    private ExecutorService threadExecutor;

    public I2PServer() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        System.out.println(Ansi.BLUE+Ansi.HIGH_INTENSITY + "Server: "+Ansi.LOW_INTENSITY
                                      + "\n"+Ansi.GREEN+"        Starting up..");

        //Προσθηκη των αλγοριθμων του bouncycastle
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        //Κατασκευη κλειδιων
        myPublicKey = Encryption.constructX509PublicKey(myPublicKeyEncoded, "RSA");
        System.out.println(""
                                      +Ansi.GREEN+"        Public key constructed.");
        myPrivateKey = Encryption.constructPKCS8PrivateKey(myPrivateKeyEncoded, "RSA");
        System.out.println(""
                                      +Ansi.GREEN+"        Private key constructed.");

        threadExecutor = Executors.newCachedThreadPool();
        System.out.println(""
                                      +Ansi.GREEN+"        Connecting to I2P..");
        manager = I2PSocketManagerFactory.createManager();
        serverSocket = manager.getServerSocket();
        session = manager.getSession();
        dest = session.getMyDestination().toBase64();

        System.out.println(""
                + "\n"+Ansi.MAGENTA+"        Server destination: "+Ansi.BLACK + dest);
        //Εμφανιση του destination με JOptionPane για πιο ευκολη αντιγραφη
        JFrame f = new JFrame();
        f.setLocationRelativeTo(null);
        f.setAlwaysOnTop(true);
        JOptionPane.showMessageDialog(f,
                new JScrollPane(new JTextArea(session.getMyDestination().toBase64())) {
                    {
                        setPreferredSize(new Dimension(200, 35));
                    }
                },
                "My Destination",
                JOptionPane.INFORMATION_MESSAGE);
        f.dispose();

        I2PThread t = new I2PThread(new ClientHandler());
        t.setDaemon(false);
        t.start();
    }

    private class ClientHandler implements Runnable {

        public void run() {
            while (true) {
                try {
                    System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Server: "+Ansi.LOW_INTENSITY
                                         + "\n"+Ansi.GREEN+"        Awaiting connections..");
                    currSock = serverSocket.accept(); //Αποδοχη συνδεσης
                    if (currSock != null) {
                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Server: "+Ansi.LOW_INTENSITY
                                         + "\n"+Ansi.GREEN+"        Successfully accepted connection.");
                        startListenThread(currSock); //Ανοιγμα thread για τη συνδεση
                    }
                } catch (I2PException ex) {
                    System.out.println(Ansi.RED+"General I2P exception!");
                } catch (ConnectException ex) {
                    System.out.println(Ansi.RED+"Error connecting!");
                } catch (SocketTimeoutException ex) {
                    System.out.println(Ansi.RED+"Timeout!");
                }
            }
        }

        private void startListenThread(I2PSocket sock) {
            threadExecutor.execute(new ListenThread(sock));
        }

        private class ListenThread implements Runnable {

            private I2PSocket sock;

            public ListenThread(I2PSocket sock) {
                this.sock = sock;
            }

            public void run() {
                try {
                    while (true) {
                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Server: "+Ansi.LOW_INTENSITY
                                         + "\n"+Ansi.GREEN+Ansi.LOW_INTENSITY+"        Client connected at port: "+Ansi.BLACK + sock.getPort()+Ansi.HIGH_INTENSITY);
                        ObjectInputStream in = new ObjectInputStream(sock.getInputStream());
                        ObjectOutputStream out = new ObjectOutputStream(sock.getOutputStream());

                        System.out.println("\n"+Ansi.GREEN+Ansi.HIGH_INTENSITY+"Following \"Authentication and Key Agreement\" protocol"+Ansi.LOW_INTENSITY);
                        //STEP 1
                        System.out.println("\n"+Ansi.YELLOW+Ansi.HIGH_INTENSITY+"**STEP 1**"+Ansi.LOW_INTENSITY);
                        //Λαμβανει to hello message απο τον client
                        String hellomsg = (String) in.readObject();
                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Client: "+Ansi.LOW_INTENSITY
                                + "\n"+Ansi.CYAN+"        Hello Message:"+Ansi.BLACK + hellomsg);

                        //STEP 2
                        System.out.println("\n"+Ansi.YELLOW+Ansi.HIGH_INTENSITY+"**STEP 2**"+Ansi.LOW_INTENSITY);
                        //Δημιουργια τυχαιου αλφαριθμιτικου 64 bit
                        final byte[] randombytes = new byte[64];
                        SecureRandom sr = new SecureRandom();
                        sr.nextBytes(randombytes);
                        String myCookie = Base64.getEncoder().encodeToString(randombytes);
                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Server: "+Ansi.LOW_INTENSITY
                                + "\n"+Ansi.CYAN+"        Server cookie: "+Ansi.BLACK + myCookie);
                        //Αποστολη τυχαιου αλφαριθμιτικου
                        out.flush();
                        out.writeObject(myCookie);
                        System.out.println(""
                                + ""+Ansi.CYAN+"        Sent server cookie.");

                        //STEP 3
                        System.out.println("\n"+Ansi.YELLOW+Ansi.HIGH_INTENSITY+"**STEP 3**"+Ansi.LOW_INTENSITY);
                        //Λαμβανει το τυχαιο αλφαριθμιτικο του client αυτο που του στειλε και τις σουιτες που υποστηριζει
                        String rCookie = (String) in.readObject();
                        String cCookie = (String) in.readObject();
                        ArrayList<String> cSymmetricAlgoOptions = (ArrayList<String>) in.readObject();
                        ArrayList<String> cHashAlgoOptions = (ArrayList<String>) in.readObject();

                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Client: "+Ansi.LOW_INTENSITY
                                + "\n"+Ansi.CYAN+"        Server cookie: "+Ansi.BLACK + rCookie
                                + "\n"+Ansi.CYAN+"        Client cookie: "+Ansi.BLACK + cCookie);

                        System.out.println(""
                                + ""+Ansi.CYAN+"        Symmetric Algorithms Supported:");
                        for (String s : cSymmetricAlgoOptions) {
                            System.out.println(""+Ansi.CYAN+"        -> "+Ansi.BLACK + s);
                        }
                        System.out.println(""
                                + ""+Ansi.CYAN+"        Hashing Algorithms Supported:");
                        for (String s : cHashAlgoOptions) {
                            System.out.println(""+Ansi.CYAN+"        -> "+Ansi.BLACK + s);
                        }

                        //Επιλογη των σουιτων που θα χρησιμοποιηθουν
                        String SymmetricAlgoSelection = "None", HashAlgoSelection = "None";
                        //(ειναι ταξινομημενες με σειρα προτιμησης)
                        for (String s : SymmetricAlgorithmsSupported) {
                            for (String c : cSymmetricAlgoOptions) {
                                if (s.equals(c)) {
                                    SymmetricAlgoSelection = c;
                                    break;
                                }
                            }
                            if (!SymmetricAlgoSelection.equals("None")) {
                                break;
                            }
                        }

                        for (String s : HashAlgorithsSupported) {
                            for (String c : cHashAlgoOptions) {
                                if (s.equals(c)) {
                                    HashAlgoSelection = c;
                                    break;
                                }
                            }
                            if (!HashAlgoSelection.equals("None")) {
                                break;
                            }
                        }
                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Sever: "+Ansi.LOW_INTENSITY+Ansi.LOW_INTENSITY
                                + "\n"+Ansi.CYAN+"        Symetric encryption algorithm selected: "+Ansi.BLACK + SymmetricAlgoSelection
                                + "\n"+Ansi.CYAN+"        Hash algorithm selected: "+Ansi.BLACK + HashAlgoSelection);

                        if (SymmetricAlgoSelection.equals("None")
                                || HashAlgoSelection.equals("None")) {
                            System.out.println(Ansi.RED+"No algorithms supported!");
                            sock.close();
                        }

                        //Step 4
                        System.out.println("\n"+Ansi.YELLOW+Ansi.HIGH_INTENSITY+"**STEP 4**"+Ansi.LOW_INTENSITY);
                        //Δημιουργια πιστοποιητικου απο το String που εχει το πιστοποιητικο που φιταχτηκε με openssl encoded
                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
                                new ByteArrayInputStream((new BASE64Decoder()).decodeBuffer(CertificateEncoded)));

                        //Αποστολη των επιλεγμενων σουιτων και του πιστοποιητικου
                        out.flush();
                        out.writeObject(SymmetricAlgoSelection);
                        out.flush();
                        out.writeObject(HashAlgoSelection);
                        out.flush();
                        out.writeObject(certificate);
                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Sever: "+Ansi.LOW_INTENSITY+Ansi.LOW_INTENSITY
                                + "\n"+Ansi.CYAN+"        Sent symetric encryption algorithm selected."
                                + "\n"+Ansi.CYAN+"        Sent hash algorithm selected."
                                + "\n"+Ansi.CYAN+"        Sent certificate.");
                        //STEP 5
                        System.out.println("\n"+Ansi.YELLOW+Ansi.HIGH_INTENSITY+"**STEP 5**"+Ansi.LOW_INTENSITY);
                        //Ληψη της συνοψης HMAC και του κρυπτογραφημενου RN
                        String RNencrypted = (String) in.readObject();
                        String HmacDigest = (String) in.readObject();
                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Client: "+Ansi.LOW_INTENSITY
                                + "\n"+Ansi.CYAN+"        Hmac digest received: "+Ansi.BLACK + HmacDigest
                                + "\n\n"+Ansi.CYAN+"        RN encrypted received:+Ansi.BLACK " + RNencrypted);
                        //Αποκρυπτογραφηση του RN με το ιδιωτικο κλειδι
                        //Αν δεν μπορει να γινει η αποκρυπτογραφηση παει να πει οτι χρησιμοποιηθηκε αλλος αλγοριθμος
                        String RNdecrypted = Encryption.Decrypt(RNencrypted, myPrivateKey, "RSA");
                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Sever: "+Ansi.LOW_INTENSITY
                                + "\n"+Ansi.CYAN+"        RN decrypted: " + RNdecrypted);

                        //Δημιουργια της συνοψης SHA256(myCookie + cCookie + RNdecrypted)
                        byte[] digest = Hashing.Hash((myCookie + cCookie + RNdecrypted).getBytes(), "SHA-256");
                        System.out.println(""
                                + ""+Ansi.CYAN+"        SHA256 Digest: " + Base64.getEncoder().encodeToString(digest));

                        //Χωρισμος της συνοψης σε δυο μερη
                        byte[] oneHalf = Arrays.copyOfRange(digest, 0, 16);
                        byte[] otherHalf = Arrays.copyOfRange(digest, 16, 32);
                        System.out.println(""
                                + ""+Ansi.CYAN+"        First half of digest: "+Ansi.BLACK + Base64.getEncoder().encodeToString(oneHalf)
                                + "\n"+Ansi.CYAN+"        Second half of digest: "+Ansi.BLACK + Base64.getEncoder().encodeToString(otherHalf));
                        //Δημιουργια κλειδιου με μεγεθος 128 bits απο το πρωτο μερος βαση του αλγοριθμου συμμετρικης κρυπτογραφησης που επιλεχτηκε 
                        //Το αλλο μισο χρεισιμοποιειται αυτουσιο ως κλειδι για δημιουργια συνοψεων HMAC
                        Key ConfidentialityKey = new SecretKeySpec(oneHalf, 0, oneHalf.length, SymmetricAlgoSelection);
                        byte[] IntegrityKey = otherHalf;
                        System.out.println(""
                                + ""+Ansi.CYAN+"        Confidntiality key: "+Ansi.BLACK + Base64.getEncoder().encodeToString(ConfidentialityKey.getEncoded())
                                + "\n"+Ansi.CYAN+"        Integrity key: "+Ansi.BLACK + Base64.getEncoder().encodeToString(IntegrityKey));
                        //Δημιουργια της συνοψης HMAC των σουιτων με τον αλγοριθμο κατακερματισμου μπου εχει επιλεχτει 
                        String myHmacDigest = HMAC.Hash(SymmetricAlgoSelection + HashAlgoSelection, IntegrityKey, HashAlgoSelection);
                        System.out.println("HMAC" + HashAlgoSelection + " Digest: "+Ansi.BLACK + Base64.getEncoder().encodeToString(digest));
                        
                        //Συγκριση της συνοψης που ληφθηκε και αυτης που δημιουργηθηκε
                        //Αν εχουν διαφορετικο μεγεθος bytes τοτε χρησιμοποιηθηκε αλλος αλγοριθμος κατακερματισμου
                        if (Base64.getDecoder().decode(myHmacDigest).length != Base64.getDecoder().decode(HmacDigest).length) {
                            System.out.println(Ansi.RED+"Client used an other hashing algorithm!");
                            sock.close();
                        }

                        //STEP 6
                        System.out.println("\n"+Ansi.YELLOW+Ansi.HIGH_INTENSITY+"**STEP 6**\n");
                        //Κρυπτογραφηση και αποστολη ενος μηνυματος με το συμμετρικο κλειδι που συμφωνηθηκε
                        String EncryptedMSG = Encryption.Encrypt("Cool", ConfidentialityKey, SymmetricAlgoSelection);
                        System.out.println("\n"+Ansi.BLUE+Ansi.HIGH_INTENSITY+"Sever: "+Ansi.LOW_INTENSITY
                                + ""+Ansi.CYAN+"        Encrypted message: " +Ansi.BLACK+ EncryptedMSG);

                        out.flush();
                        out.writeObject(EncryptedMSG);
                        System.out.println(""
                                + ""+Ansi.CYAN+"        Sent encrypted message. ");
//                        sock.close();
                    }
                } catch (ConnectException ex) {
                    System.out.println("Error connecting!");
                } catch (SocketTimeoutException ex) {
                    System.out.println("Timeout!");
                } catch (IOException ex) {
                    System.out.println("General read/write-exception!");
                } catch (ClassNotFoundException ex) {
                    System.out.println("Class <Msg> is missing!");
                } catch (CertificateException ex) {
                    Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidAlgorithmParameterException ex) {
                    Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
                    System.out.println("Client used an other symmetric encryption algorithm!");
                }
            }
        }

    }

    public static void main(String[] args) {
        try {
            new I2PServer();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    // <editor-fold defaultstate="collapsed" desc="Colors Variables">     + +
    public final class Ansi {

        // Color code strings from:
        // http://www.topmudsites.com/forums/mud-coding/413-java-ansi.html
        public static final String SANE = "\u001B[0m";

        public static final String HIGH_INTENSITY = "\u001B[1m";
        public static final String LOW_INTENSITY = "\u001B[2m";

        public static final String ITALIC = "\u001B[3m";
        public static final String UNDERLINE = "\u001B[4m";
        public static final String BLINK = "\u001B[5m";
        public static final String RAPID_BLINK = "\u001B[6m";
        public static final String REVERSE_VIDEO = "\u001B[7m";
        public static final String INVISIBLE_TEXT = "\u001B[8m";

        public static final String BLACK = "\u001B[30m";
        public static final String RED = "\u001B[31m";
        public static final String GREEN = "\u001B[32m";
        public static final String YELLOW = "\u001B[33m";
        public static final String BLUE = "\u001B[34m";
        public static final String MAGENTA = "\u001B[35m";
        public static final String CYAN = "\u001B[36m";
        public static final String WHITE = "\u001B[37m";

        public static final String BACKGROUND_BLACK = "\u001B[40m";
        public static final String BACKGROUND_RED = "\u001B[41m";
        public static final String BACKGROUND_GREEN = "\u001B[42m";
        public static final String BACKGROUND_YELLOW = "\u001B[43m";
        public static final String BACKGROUND_BLUE = "\u001B[44m";
        public static final String BACKGROUND_MAGENTA = "\u001B[45m";
        public static final String BACKGROUND_CYAN = "\u001B[46m";
        public static final String BACKGROUND_WHITE = "\u001B[47m";

    }// </editor-fold>
}
