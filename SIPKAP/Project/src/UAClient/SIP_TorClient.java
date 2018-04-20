package UAClient;

import ProtocolPackets.SIP_Packet;
import Security.Digest;
import Security.EncryptionTool;
import StsKeyAgreement.STSKAP;
import Utils.ColorPrint;
import Utils.Serializer;
import com.msopentech.thali.java.toronionproxy.*;
import java.io.*;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author icsd12015 icsd11162
 */
public final class SIP_TorClient implements Runnable {

    //O Security Provider einai o BouncyCastleProvider
    private final Provider bcprov = new BouncyCastleProvider();

    //O algorithmos gia tin kruptografisi
    private final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private final boolean ENCRYPTION_USE_IV = true;

    private final Socket sock;
    private final ObjectOutputStream out;
    private final ObjectInputStream in;

    private final HashMap<String, String> calls;

    private boolean keepRunning;

    private final String realm;
    private final String address;
    private final String branch;

    private final STSKAP STSkeyagree;

    public SIP_TorClient (String address, int port, String logsFile) throws IOException, SecurityException, InterruptedException {
        //Orismos tou darcula LookAndFeel
        try {
            javax.swing.UIManager.setLookAndFeel("com.bulenkov.darcula.DarculaLaf");
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException |
                 javax.swing.UnsupportedLookAndFeelException ex) {
            System.err.println(ex);
        }

        this.calls = new HashMap<>();

        //Sundesi tou socket ston proxy mesw Tor
        OnionProxyManager onionProxyManager = new JavaOnionProxyManager(
                new JavaOnionProxyContext(new File(logsFile)));

        int totalSecondsPerTorStartup = 4 * 60;
        int totalTriesPerTorStartup = 5;
        // Start the Tor Onion Proxy

        if (onionProxyManager.startWithRepeat(totalSecondsPerTorStartup, totalTriesPerTorStartup) == false) {
            throw new IOException("Error Starting Tor.");
        }

        // Start a hidden service listener
        int localOnionPort = onionProxyManager.getIPv4LocalHostSocksPort();
        try {
            this.sock = Utilities.socks4aSocketConnection(address, port, "127.0.0.1", localOnionPort);
        } catch (IOException ex) {
            onionProxyManager.stop();
            throw ex;
        }

        this.out = new ObjectOutputStream(sock.getOutputStream());
        this.out.flush();
        this.in = new ObjectInputStream(sock.getInputStream());

        this.address = address + ":" + port;
        this.realm = address;

        //Tyxaio id gia branch
        this.branch = UUID.randomUUID().toString().split("-")[0];

        //Dimiourgia tou STSKAP me BouncyCastleProvider
        this.STSkeyagree = new STSKAP(new BouncyCastleProvider());

        //kalei tin doKeyAgreement se rolo REFERRER diladi autos pou ksekinaei tin sumfwnia kleidiou tis STSKAP
        if (!this.STSkeyagree.doKeyAgreement(STSKAP.Role.REFERRER, in, out)) {
            throw new SecurityException("Failed on Key Agreement with Proxy");
        }

    }

    //Oso trexei dexetai sip paketa, ta apokruptografei kai ta dinei stin handle na ta xeiristei katallila
    @Override
    public void run () {
        keepRunning = true;
        while (keepRunning) {
            try {
                //Diavasma paketou kai apokwdikopoihsh apo Base64
                byte[] encrypted_data = Base64.decode((String) in.readObject());
                //Apokruptografisi paketou
                byte[] decrypted_data = EncryptionTool.Decrypt(encrypted_data, this.STSkeyagree.getCommonKey(), ENCRYPTION_ALGORITHM, ENCRYPTION_USE_IV, bcprov);
                //Metatropi apokruptografimenwn bytes se antikeimeno SIP_Packet
                SIP_Packet packet = (SIP_Packet) Serializer.deserialize(decrypted_data);

                System.out.println("");
                ColorPrint.print("Client at: " + this.sock.getLocalSocketAddress() + " Received an Encrypted SIP Packet from Proxy at: " + sock.getRemoteSocketAddress(), ColorPrint.ANSI_CYAN);
                ColorPrint.print("Decrypted with the Common Secret Key: \n", ColorPrint.ANSI_CYAN);
                packet.colorPrint(); //Tupwsi paketou

                //klisi tis handle gia na diaxeiristei to paketo
                handle(packet);
            } catch (SocketTimeoutException ex) {
            } catch (IOException ex) {
                ex.printStackTrace();
                keepRunning = false;
            } catch (ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                     BadPaddingException |
                     NoSuchProviderException ex) {
                ex.printStackTrace();
            }
        }
    }

    //Kanei tis analoges energeies gia to kathe paketo pou lifthike
    public void handle (SIP_Packet packet) {
        switch (packet.getMethod()) {
            case INVITE: //An to SIP paketo exei methodo INVITE

                //Dimiourgia kai apostoli sip paketou me code 180 RINGING vasi tou paketou pou irthe
                SIP_Packet ringing = generateResponceMessage(SIP_Packet.RESPONCE_CODES.RINGING, packet, this.branch);

                try {
                    //Kruptografisi kai apostoli paketou ston proxy
                    encryptAndSend(ringing);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }

                //Emfanisi dialogou gia apodoxi tis klisis kai an ginei apodoxi dimiourgia sip paketou me code 200 OK vasi tou paketou pou irthe
                SIP_Packet responce = null;
                java.awt.Toolkit.getDefaultToolkit().beep(); // *BEEP*
                JFrame ontop = new JFrame();
                ontop.setAlwaysOnTop(true);
                if (JOptionPane.showOptionDialog(ontop, "Contact <sip:" + packet.getFromHeader() + "> is calling...", "Incoming Call",
                                                 JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE,
                                                 null, new String[]{"Accept", "Hang up"}, null) == 0) {

                    responce = generateResponceMessage(SIP_Packet.RESPONCE_CODES.OK, packet, this.branch);
                    responce.setCSeqMethod(packet.getCSeqMethod());

                } else {

                }
                try {
                    //Kruptografisi kai apostoli paketou ston proxy
                    encryptAndSend(responce);
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                break;
            case RESPONSE: //An to SIP paketo exei methodo RESPONSE
                switch (packet.getCode()) {
                    case SIP_Packet.RESPONCE_CODES.PROXY_AUTHENTICATION_REQUIRED: //An exei to code PROXY_AUTHENTICATION_REQUIRED
                        if (packet.hasAuthenticationHeader()) { //An to sip paketo periexei Authentication Header
                            if (packet.getAuthencticateRealm().equals(this.realm)) {
                                if (this.calls.containsKey(packet.getCallID())) { //An uparxei klisei me Call-ID tou paketou
                                    try {
                                        //An i methodos tou sequence tou paketou diladi an to responce einai apantisei se paketo INVITE
                                        if (packet.getCSeqMethod().equals(SIP_Packet.Method.INVITE)) {
                                            //Dimiourgia ACK sip paketou vasi tou paketou pou irthe
                                            SIP_Packet ack = generateACKPacket(packet);
                                            //Kruptografisi kai apostoli paketou ston proxy
                                            encryptAndSend(ack);
                                        }

                                        //Dimiourgia sip paketou gia authorization vasi tou paketou pou irthe
                                        SIP_Packet request = generateAuthorizationPacket(packet, packet.getCSeqMethod());
                                        //Kruptografisi kai apostoli paketou ston proxy
                                        encryptAndSend(request);

                                    } catch (NoSuchAlgorithmException | IOException ex) {
                                        ex.printStackTrace();
                                    }
                                }
                            }
                        } else {

                        }
                        break;
                    case SIP_Packet.RESPONCE_CODES.OK: //An exei to code OK
                        //An i methodos tou sequence tou paketou diladi an to responce einai apantisei se paketo INVITE
                        if (packet.getCSeqMethod().equals(SIP_Packet.Method.INVITE)) {
                            //Dimiourgia ACK sip paketou vasi tou paketou pou irthe
                            SIP_Packet ack = generateACKPacket(packet);
                            try {
                                //Kruptografisi kai apostoli paketou ston proxy
                                encryptAndSend(ack);
                            } catch (IOException ex) {
                                ex.printStackTrace();
                            }
                        }
                        break;
                }
                break;
        }
    }

    //Methodos gia tin enarksi enos call gia REGISTER se ena PROXY
    public void doREGISTER (String address) {
        String callID = UUID.randomUUID().toString().split("-")[4];
        String tag = UUID.randomUUID().toString().split("-")[0];
        calls.put(callID, address);
        //Dimiourgia enos neou REGISTER sip paketou
        SIP_Packet request = new SIP_Packet(
                SIP_Packet.Method.REGISTER,
                address,
                new String[]{address, this.branch},
                address);
        request.setCallID(callID);
        request.setFromTag(tag);
        try {
            //Kruptografisi kai apostoli paketou ston proxy
            encryptAndSend(request);
            out.flush();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    //Methodos gia tin enarksi enos call gia INVITE se ena CLIENT
    public void doINVITE (String from, String to) {
        String callID = UUID.randomUUID().toString().split("-")[4];
        String tag = UUID.randomUUID().toString().split("-")[0];
        calls.put(callID, to);
        //Dimiourgia enos neou INVITE sip paketou
        SIP_Packet request = new SIP_Packet(
                SIP_Packet.Method.INVITE,
                from,
                new String[]{address, this.branch},
                to);
        request.setCallID(callID);
        request.setFromTag(tag);
        try {
            //Kruptografisi kai apostoli paketou ston proxy
            encryptAndSend(request);
            out.flush();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    //Methodos gia ti kruptografisi paketwn me to summetriko kleidi kai apostoli
    public void encryptAndSend (SIP_Packet packet) throws IOException {
        try {
            //Kruptografisi paketou me to koino summetriko kleidi tou proxy
            byte[] encrypted = EncryptionTool.Encrypt(packet.getBytes(), this.STSkeyagree.getCommonKey(), ENCRYPTION_ALGORITHM, ENCRYPTION_USE_IV, bcprov);
            //Metatropi se Base64 String kai apostoli ston proxy
            out.writeObject(Base64.toBase64String(encrypted));
            out.flush();
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | NoSuchPaddingException | BadPaddingException | NoSuchProviderException |
                 InvalidAlgorithmParameterException ex) {
            ex.printStackTrace();
        }
    }

    //Methodos gia ti dimiourgia Authorization sip paketou vasi proigoumenou sip paketou
    public SIP_Packet generateAuthorizationPacket (SIP_Packet responce, SIP_Packet.Method seq_method) throws NoSuchAlgorithmException {

        //Extract ta stoixeia tou authentication header tou paketou
        String algorithm = responce.getAuthencticateAlgorithm();
        String realm = responce.getAuthencticateRealm();
        byte nonce[] = Base64.decode(responce.getAuthencticateNonce());
        String pass = requestPassword(responce.getFromHeaderName()); //Epistrefei ton kwdiko tou client vasi tou username
        byte cnonce[] = Digest.generateSalt(8);

        //Dimiourgia sunopsis me xrisi tou algorithmou kai tou nonce pou orise to paketo
        String digest = Base64.toBase64String(Digest.HashWithSalt(pass.getBytes(), nonce, cnonce, algorithm));

        //Dimiourgia sip paketou me ta stoixeia auta sto authorization header
        SIP_Packet request = new SIP_Packet(seq_method, responce.getFromHeader(), new String[]{address, this.branch}, responce.getToHeader());
        //Orismos Call-ID kai CSeq
        request.setCallID(responce.getCallID());
        request.setCSeq(2);

        //Orismos parametrwn tou Authorization Header
        request.setAuthorization(true);
        request.setAuthorizationUsername(responce.getFromHeader().split("@")[0].toLowerCase());
        request.setAuthorizationRealm(realm);
        request.setAuthorizationNonce(responce.getAuthencticateNonce());
        request.setAuthorizationCnonce(Base64.toBase64String(cnonce));
        request.setAuthorizationResponce(digest);

        return request;
    }

    //Dimiourgia Ack sip paketou vasi proigoumenou sip paketou
    public SIP_Packet generateACKPacket (SIP_Packet responce) {
        SIP_Packet ack = new SIP_Packet(SIP_Packet.Method.ACK, responce.getFromHeader(), new String[]{address, this.branch},
                                        responce.getToHeader());
        ack.setCallID(responce.getCallID());
        return ack;
    }

    //Dimiourgia RESPONCE sip paketou me code responce vasi proigoumenou sip paketou
    public SIP_Packet generateResponceMessage (int code, SIP_Packet request, String ID) {

        //Dimiourgia kai apostoli RESPONCE sip paketou me ton code kai to from, to tou proigoumenou paketou
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
        responce.addVia(new String[]{lastVia[0], lastVia[1], this.sock.getRemoteSocketAddress().toString().split(":")[0]});

        //Meiwsi twn Max Forwards
        responce.setMaxForwards(request.getMaxForwards() - 1);

        return responce;
    }

    //Methodos gia tin epistrofi kwdikwn analoga ton logariasmo client
    //(pou uparxoun ston registrar (vasi) tou antistoixou proxy tou client
    public String requestPassword (String uname) {
        switch (uname) {
            case "Alice":
                return "alicepass";
            case "Bob":
                return "bobpass";
            default:
                throw new AssertionError();
        }
    }
}
