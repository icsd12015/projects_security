package UAServer;

import ProtocolPackets.SIP_Packet;
import Security.Digest;
import Security.EncryptionTool;
import StsKeyAgreement.STSKAP;
import Utils.ColorPrint;
import Utils.Serializer;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.*;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author icsd12015 icsd11162
 */
public class SIP_Proxy implements Runnable {

    //O Security Provider einai o BouncyCastleProvider
    private final Provider bcprov = new BouncyCastleProvider();

    //O algorithmos gia tin kruptografisi
    private final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private final boolean ENCRYPTION_USE_IV = true;

    private final ServerSocket serverSock;
    private boolean running;

    private final HashMap<String, UAS_Thread> clients;
    private final DBServInterface dbserver;

    private final String HASH_ALGORITHM = "MD5";

    private final String realm;

    private final boolean localInstances = true;

    public SIP_Proxy (String hostname, int port, int backlog, String registrar_url) throws IOException, NotBoundException {
        this.clients = new HashMap<>();

        //Pairnw tin anafora sto Registrar vasi tou url me RMI
        this.dbserver = (DBServInterface) Naming.lookup(registrar_url);

        //Bind tou ServerSocket
        this.serverSock = new ServerSocket(port, backlog, InetAddress.getByName(hostname));
        ColorPrint.print("Started server at: " + hostname + ":" + port + ".\n", ColorPrint.ANSI_GREEN);

        //To realm an px LocalSocketAddress == localhost/127.0.0.1:5060 -> realm = 127.0.0.1 )
        this.realm = serverSock == null ? null : serverSock.getLocalSocketAddress().toString().split("/")[1].split(":")[0];
    }

    @Override
    public void run () {
        running = true;
        while (running) {
            try {
                //Apodoxi tou incoming connection
                Socket client = serverSock.accept();
                addClient(client);
            } catch (IOException e) {
                ColorPrint.print("Server error: " + e, ColorPrint.ANSI_RED);
                System.exit(1);
            }
        }
    }

    //Anoigei ena Server Thread gia to connection epeita
    //Ektelei kai elegxei tin epituxia tou Station-to-Station Key Agreement Protocol me ton client
    //kai an ola pane kala prosthetei to thread sto HashMap me tous energous clients
    public void addClient (Socket sock) {
        System.out.println("");
        ColorPrint.print("Proxy at: " + this.serverSock.getLocalSocketAddress() + " accepted connection from: " + sock.getRemoteSocketAddress().toString().split("/")[1], ColorPrint.ANSI_CYAN);
        UAS_Thread client = new UAS_Thread(sock);
        try {
            client.open();
            //Ektelesi tou STS KAP
            boolean ProtocolSucceed = client.STSkeyagree.doKeyAgreement(STSKAP.Role.REFEREE, client.in, client.out);
            if (ProtocolSucceed) { //An epituxei
                synchronized (client) { //Anamoni 1s gia swsti emfanisi minimatwn
                    client.wait(1000);
                }
                //Ekkinisi tou thread kai prosthiki sto map me ta energa client connections
                client.start();
                clients.put(client.ID, client);
            }
        } catch (IOException | InterruptedException e) {
            ColorPrint.print("Error while opening thread " + client.ID + ":\n\t" + e, ColorPrint.ANSI_RED);
            e.printStackTrace();
            return;
        }
    }

    //Kanei tis analoges energeies gia to kathe paketo pou lifthike
    public synchronized void handle (String ID, SIP_Packet request) {
        switch (request.getMethod()) {
            case REGISTER: //An to SIP paketo exei methodo REGISTER
                if (((request.getFromHeader().split("@")[1]).equals(this.realm))) { //An anaferetai sto realm autou tou Proxy
                    if (request.hasAuthorizationHeader()) { //An to sip paketo periexei Authorization Header
                        if (authorize(request, ID)) { //An epituxei to authorization vasi twn stoixeiwn tou Authorization Header kai twn stoixeiwn tou registered client
                            SIP_Packet ok = generateResponcePacket(SIP_Packet.RESPONCE_CODES.OK, request, ID);
//                            clients.get(ID).address = request.peekLastViaHeader()[0];
                            clients.get(ID).address = request.getToHeader(); //Orismos tou address tou client me ti dieuthinsi pou edwse
                            //Kruptografisi kai apostoli paketou OK ston client
                            clients.get(ID).encryptAndSend(ok);
                        }
                    } else {
                        //Dimiourgia sip paketou me code 407 PROXY_AUTHENTICATION_REQUIRED pou periexei katalilo authenticate header
                        SIP_Packet responce = generateAuthPacket(request, ID);
                        //Kruptografisi kai apostoli paketou ston client
                        clients.get(ID).encryptAndSend(responce);
                    }
                }
                break;
            case INVITE: //An to SIP paketo exei methodo INVITE
                //An to paketo proerxetai apo client autou tou realm
                //(H' an ola trexoun topika epeidi ta realms einai idia an uparxei mono ena ViaHeader diladi einai i prwti apostoli tou paketou apeutheias apo ton client)
                if ((!localInstances && (request.getFromHeader().split("@")[1]).equals(this.realm)) || (localInstances && request.getViaHeaders().size() == 1)) {
                    if (!request.hasAuthorizationHeader()) { //An to sip paketo periexei Authorization Header
                        //Dimiourgia sip paketou me code 407 PROXY_AUTHENTICATION_REQUIRED pou periexei katalilo authenticate header
                        SIP_Packet responce = generateAuthPacket(request, ID);
                        //Kruptografisi kai apostoli paketou ston client
                        clients.get(ID).encryptAndSend(responce);
                    } else {
                        if (authorize(request, ID)) { //An epituxei to authorization vasi twn stoixeiwn tou Authorization Header kai twn stoixeiwn tou registered client
                            clients.get(ID).address = request.peekLastViaHeader()[0];
                            //Dimiourgia sip paketou me code 100 TRYING vasi tou paketou pou lifthike
                            SIP_Packet trying = generateResponcePacket(SIP_Packet.RESPONCE_CODES.TRYING, request, ID);
                            //Kruptografisi kai apostoli paketou ston client
                            clients.get(ID).encryptAndSend(trying);
                            forwardToAnotherProxy(request, ID); //Prowthisi tou paketou ston Proxy tou paralipti
                        }
                    }
                } else { //An proerxetai apo client allou proxy
                    clients.get(ID).IP = request.peekLastViaHeader()[0].split(":")[0]; //Thetei to IP tou Server Thread
                    forward(request, ID); //Prowthisi tou paketou ston paralipti
                    //Dimiourgia sip paketou me code 100 TRYING
                    SIP_Packet trying = generateResponcePacket(SIP_Packet.RESPONCE_CODES.TRYING, request, ID);
                    //Kruptografisi kai apostoli paketou ston client
                    clients.get(ID).encryptAndSend(trying);
                }
                break;
            case ACK: //An to SIP paketo exei methodo INVITE
                //An to paketo proerxetai apo client autou tou realm
                //(H' an ola trexoun topika epeidi ta realms einai idia an uparxei mono ena ViaHeader diladi einai i prwti apostoli tou paketou apeutheias apo ton client)
                if ((!localInstances && (request.getFromHeader().split("@")[1]).equals(this.realm)) || (localInstances && request.getViaHeaders().size() == 1)) {
                    if (this.clients.get(ID).address != null) { //An stin sundesi exei oristei address (meta apo REGISTER)
                        if (this.clients.get(ID).address.split(":")[0].equals(request.getFromHeader().split("@")[1].split(":")[0])) {
                            forwardToAnotherProxy(request, ID); //Prowthisi tou paketou ston Proxy tou paralipti
                        }
                    }
                } else { //An proerxetai apo client allou proxy
                    forward(request, ID); //Prowthisi tou paketou ston paralipti
                }
                break;
            case RESPONSE: //An to SIP paketo exei methodo RESPONSE
                switch (request.getCode()) {
                    case SIP_Packet.RESPONCE_CODES.RINGING:
                    case SIP_Packet.RESPONCE_CODES.OK:
                        SIP_Packet responce = generateResponcePacket(request.getCode(), request, ID);
                        responce.setCSeqMethod(request.getCSeqMethod()); //Orismos tou CSeq Method
                        String[] lastvia = responce.removeLastViaHeader(); //Afairesi teleutaiou header

                        if (lastvia.length == 3) { //An to teleutaio via header exei received tag

                            //Vriskei ton nima sundesis me ti dieuthinsi tou teleutaiou via (anapodi dromologisi)
                            UAS_Thread receipentThread = getUASbyAddress(responce.peekLastViaHeader()[0]);

                            if (receipentThread != null) {
                                //Kruptografisi kai apostoli paketou ston client
                                receipentThread.encryptAndSend(responce);
                            } else {
                            }
                        }
                        break;
                }
        }
    }

    //Methodos gia prowthisi paketwn se clients autou tou Proxy
    public synchronized void forward (SIP_Packet request, String ID) {
        //Dimiourgia sip paketou gia prowthisi tou paketou pou lifthike
        SIP_Packet responce = generateForwadingPacket(request, ID);

        //Vriskei to energo nima sundesis me ton paralipti
        UAS_Thread receipentThread = getUASbyAddress(request.getToHeader());
        if (receipentThread != null) {
            //Kruptografisi kai apostoli prowthoumenou paketou ston client
            receipentThread.encryptAndSend(responce);
            //Orizei tin dieuthinsi tis sundesis me ton allon proxy vasi tou teleutaiou via header
            clients.get(ID).address = request.peekLastViaHeader()[0];
        } else {

        }
    }

    //Methodos gia prowthisi paketwn se clients allwm Proxies
    public synchronized void forwardToAnotherProxy (SIP_Packet request, String ID) {
        try {
            //An uparxei idi sundesi me ton Proxy toy paralipti to pairnei apo to HashMap vasi tou address pou ginetai extract apo to To Header
            UAS_Thread connection = getUASbyIP(request.getToHeader().split("@")[1]);

            if (connection == null) { //An de uparxei idi sundesi me ton Proxy toy paralipti

                //Dimiourgia Server Thread gia tin sundesi me to allo Proxy (i dieuthinsi ginetai extract apo to To Header)
                Socket pipe = new Socket(request.getToHeader().split("@")[1], localInstances ? 7061 : 5060, InetAddress.getByName("localhost"), 7160);

                //Dimiourgia Server Thread
                connection = new UAS_Thread(pipe);
                //Orismos tou IP
                connection.IP = request.getToHeader().split("@")[1].split(":")[0];
                connection.open(); //Anoigma
                //Ekkinisi protokolou sumfwnias kleidiou
                if (connection.STSkeyagree.doKeyAgreement(STSKAP.Role.REFERRER, connection.in, connection.out)) {
                    //An epiteuxhtei sumfwnia amoivaiou kleidiou
                    connection.start(); //Ekkinisi nimatos
                    clients.put(connection.ID, connection); //Prosthiki sto HashMap
                } else {
                    connection.close();
                    return;
                }
            }
            //Dimiourgia sip paketou gia prowthisi tou paketou pou lifthike
            SIP_Packet responce = generateForwadingPacket(request, ID);
            //Kruptografisi kai apostoli prowthoumenou paketou ston client
            connection.encryptAndSend(responce);

        } catch (IOException ex) {
            ex.printStackTrace();
            return;
        }
    }

    //Methodos gia dimiourgia paketou pou periexei katalilo Authentication Header vasi tou paketou pou lifthike
    public SIP_Packet generateAuthPacket (SIP_Packet request, String ID) {
        //Dimiourgia 
        SIP_Packet auth = new SIP_Packet(SIP_Packet.RESPONCE_CODES.PROXY_AUTHENTICATION_REQUIRED, request.getFromHeader(), request.getToHeader());

        //Orismos Call-ID, CSeq number, CSeq method
        auth.setCallID(request.getCallID());
        auth.setCSeq(request.getCSeq());
        auth.setCSeqMethod(request.getMethod());

        //Prosthiki twn via headers pou eixe to proigoumeno paketo kai sto teleutaio via vazoume to tag received me auto to address
        ArrayList<String[]> viaHeaders = request.getViaHeaders();
        for (int i = 0; i < viaHeaders.size() - 1; i++) {
            String[] via = viaHeaders.get(i);
            auth.addVia(via);
        }
        String[] lastVia = viaHeaders.get(viaHeaders.size() - 1);
        auth.addVia(new String[]{lastVia[0], lastVia[1], this.clients.get(ID).IP});

        //Orismos parametrwn tou Authentication Header
        auth.setAuthenticate(true);
        auth.setAuthencticateRealm(this.realm);
        String nonce = Base64.toBase64String(Digest.generateSalt(16)); //Dimiourgia salt
        this.clients.get(ID).nonce = nonce; //Orismos tou salt tis sundesis
        auth.setAuthencticateNonce(nonce);
        auth.setAuthencticateAlgorithm(HASH_ALGORITHM);

        return auth;
    }

    //Methodos gia dimiourgia prowthoumenou paketou vasi tou paketou pou lifthike
    public SIP_Packet generateForwadingPacket (SIP_Packet request, String ID) {

        //Dimiourgia sip paketou me to idio Method, From kai To Header
        SIP_Packet forward = new SIP_Packet(request.getMethod(), request.getFromHeader(), request.getToHeader());

        //Orismos Call-ID, CSeq number, CSeq method
        forward.setCallID(request.getCallID());
        forward.setCSeq(request.getCSeq());
        forward.setCSeqMethod(request.getMethod());

        //Prosthiki twn via headers pou eixe to proigoumeno paketo kai sto teleutaio via vazoume to tag received me auto to address
        ArrayList<String[]> viaHeaders = request.getViaHeaders();
        for (int i = 0; i < viaHeaders.size() - 1; i++) {
            String[] via = viaHeaders.get(i);
            forward.addVia(via);
        }
        String[] lastVia = viaHeaders.get(viaHeaders.size() - 1);
        forward.addVia(new String[]{lastVia[0], lastVia[1], this.clients.get(ID).IP});
        forward.addVia(new String[]{realm + ":" + this.serverSock.getLocalPort(), ID});

        //Meiwsi twn MaxForwards
        forward.setMaxForwards(request.getMaxForwards() - 1);

        return forward;
    }

    //Methodos gia dimiourgia RESPONCE paketou me code vasi tou paketou pou lifthike
    public SIP_Packet generateResponcePacket (int code, SIP_Packet request, String ID) {

        //Dimiourgia sip paketou me to code kai to idio From kai To Header
        SIP_Packet responce = new SIP_Packet(code, request.getFromHeader(), request.getToHeader());

        //Orismos Call-ID, CSeq number, CSeq method
        responce.setCallID(request.getCallID());
        responce.setCSeq(request.getCSeq());
        responce.setCSeqMethod(request.getMethod());

        //Prosthiki twn via headers pou eixe to proigoumeno paketo kai sto teleutaio via vazoume to tag received me auto to address
        ArrayList<String[]> viaHeaders = request.getViaHeaders();
        for (int i = 0; i < viaHeaders.size() - 1; i++) {
            String[] via = viaHeaders.get(i);
            responce.addVia(via);
        }
        String[] lastVia = viaHeaders.get(viaHeaders.size() - 1);
        responce.addVia(new String[]{lastVia[0], lastVia[1], this.clients.get(ID).IP});

        //Meiwsi twn MaxForwards
        responce.setMaxForwards(request.getMaxForwards() - 1);

        return responce;
    }

    //Methodos gia elegxo Authorization paketou
    public boolean authorize (SIP_Packet request, String ID) {

        //Pairnw ta stoixeia tou Authorization Header
        String r_realm = request.getAuthorizationRealm();
        String r_username = request.getAuthorizationUsername();
        String r_nonce = request.getAuthorizationNonce();
        String r_cnonce = request.getAuthorizationCnonce();
        String r_responce = request.getAuthorizationResponce();

        byte[] nonce = Base64.decode(this.clients.get(ID).nonce);

        //Elegxos gia tin orthotita tous
        if (request.getCSeq() > 1 && r_realm.equals(realm) && Arrays.equals(Base64.decode(r_nonce), nonce)) {

            byte[] c_nonce = Base64.decode(r_cnonce);

            try {
                //O Registar vriskei kai uplogizei vasi tou algorithmou katakermatismou ti sunopsi tou kwdikou tou client vasi tou username me ta nonces
                String digest = this.dbserver.getClientDigest(r_username, nonce, c_nonce, HASH_ALGORITHM);
                return r_responce.equals(digest); //Sugkrisi sunopsewn
            } catch (NoSuchAlgorithmException ex) {
            } catch (RemoteException ex) {
                ex.printStackTrace();
            }
        }
        return false;
    }

    //Mehtodos gia euresi Server Thread vasi address
    private UAS_Thread getUASbyAddress (String address) {
        for (String ID : clients.keySet()) {
            if (address.equals(clients.get(ID).address)) {
                return clients.get(ID);
            }
        }
        return null;
    }

    //Mehtodos gia euresi Server Thread vasi IP
    private UAS_Thread getUASbyIP (String IP) {
        for (String ID : clients.keySet()) {
            if (IP.equals(clients.get(ID).IP)) {
                return clients.get(ID);
            }
        }
        return null;
    }

    public void stop () {
        try {
            serverSock.close();
        } catch (IOException ex) {
        }
        running = false;
    }

    //Klasi Server Thread gia tis epimerous sundesis tou server me tous Clients kai ta alla Proxies
    class UAS_Thread extends Thread {

        private Socket pipe;
        private String IP;
        private String ID;
        private ObjectInputStream in;
        private ObjectOutputStream out;
        private boolean keepRunning;
        private String address;

        private String nonce;

        private STSKAP STSkeyagree; //Key Agreement instance

        UAS_Thread (Socket socket) {
            this.pipe = socket;
            String uuid = UUID.randomUUID().toString();
            //Dimiourgia tuxaiou ID
            this.ID = uuid.substring(uuid.lastIndexOf("-") + 1);
            //To IP apo to address
            this.STSkeyagree = new STSKAP(new BouncyCastleProvider());
        }

        @Override
        public void run () {
            keepRunning = true;
            ColorPrint.print("Connection thread: " + ID + " is running.\n", ColorPrint.ANSI_BLUE);
            while (keepRunning) {
                try {
                    //Diavasma paketou kai apokwdikopoihsh apo Base64
                    byte[] encrypted_data = Base64.decode((String) in.readObject());

                    //Apokruptografisi paketou
                    byte[] decrypted_data = EncryptionTool.Decrypt(encrypted_data, this.STSkeyagree.getCommonKey(), ENCRYPTION_ALGORITHM, ENCRYPTION_USE_IV, bcprov);
                    //Metatropi apokruptografimenwn bytes se antikeimeno SIP_Packet
                    SIP_Packet packet = (SIP_Packet) Serializer.deserialize(decrypted_data);

                    System.out.println("");
                    ColorPrint.print("Proxy at: " + serverSock.getLocalSocketAddress()
                            + " Received an Encrypted SIP Packet from: " + this.pipe.getRemoteSocketAddress().toString().split("/")[1], ColorPrint.ANSI_CYAN);
                    ColorPrint.print("Decrypted with the Common Secret Key: \n", ColorPrint.ANSI_CYAN);
                    packet.colorPrint(); //Tupwsi paketou

                    //klisei tis handle gia na diaxeiristei to paketo
                    handle(this.ID, packet);
                } catch (IOException e) {
                    e.printStackTrace();
                    ColorPrint.print("Error communication with thread " + ID + ":\n\t" + e, ColorPrint.ANSI_RED);
                    try {
                        this.close();
                    } catch (IOException ex) {
                        ColorPrint.print("Error while closing thread " + ID + ":\n\t" + e, ColorPrint.ANSI_RED);
                    }
                    keepRunning = false;
                } catch (ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                         BadPaddingException |
                         NoSuchProviderException ex) {
                    ex.printStackTrace();
                }
            }
        }

        //Methodos gia ti kruptografisi paketwn me to summetriko kleidi kai apostoli
        public void encryptAndSend (SIP_Packet packet) {
            try {
                //Kruptografisi paketou me to koino summetriko kleidi tou proxy
                byte[] encrypted = EncryptionTool.Encrypt(packet.getBytes(), this.STSkeyagree.getCommonKey(), ENCRYPTION_ALGORITHM, ENCRYPTION_USE_IV, bcprov);
                //Metatropi se Base64 String kai apostoli ston proxy
                out.writeObject(Base64.toBase64String(encrypted));
                out.flush();
            } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | NoSuchPaddingException | BadPaddingException | NoSuchProviderException |
                     InvalidAlgorithmParameterException ex) {
                ex.printStackTrace();
            }
        }

        public void open () throws IOException {
            out = new ObjectOutputStream(pipe.getOutputStream());
            out.flush();
            in = new ObjectInputStream(pipe.getInputStream());
        }

        public void close () throws IOException {
            if (pipe != null) {
                pipe.close();
            }
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
        }

    }

}
