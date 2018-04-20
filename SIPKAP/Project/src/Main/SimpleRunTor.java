package Main;


import Registrar.DatabaseServer;
import UAClient.SIP_TorClient;
import UAServer.SIP_TorProxy;
import Utils.ColorPrint;
import java.io.IOException;
import java.rmi.NotBoundException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 *
 * @author icsd12015
 */
public class SimpleRunTor extends Thread {

    private CountDownLatch countdown;

    public static void main (String[] args) {
        new SimpleRunTor().start();
    }

    @Override
    public void run () {
        countdown = new CountDownLatch(1);
        try {
            //Dimiourgia twn duo Database Servers me ta stoixeia twn Clients
            DatabaseServer Ra = new DatabaseServer("SIP_RegistrarA", 7080, "./db/clientsA.db");
            DatabaseServer Rb = new DatabaseServer("SIP_RegistrarB", 7080, "./db/clientsB.db");

            //Dimiourgia twn duo Proxy Servers sta ports 7060 kai 7061 topika kai 5060 kai 5060 sta Tor Services
            SIP_TorProxy Pa = new SIP_TorProxy("localhost", 7060, 5060, Ra.getURL(), "./logs/Tor/pA");
            SIP_TorProxy Pb = new SIP_TorProxy("localhost", 7061, 5060, Rb.getURL(), "./logs/Tor/pB");

            //Enarksi twn Proxies se threads
            Thread PaThread = new Thread(Pa);
            PaThread.start();

            Thread PbThread = new Thread(Pb);
            PbThread.start();

            //Perimenei 10 second
            countdown.await(10, TimeUnit.SECONDS);

            //Dimiourgia tou Client Alice kai sundesi tou me ton Proxy me to HostName pou pire apo to Tor diktuo sto port 5060
            SIP_TorClient alice = new SIP_TorClient(Pa.getHostName(), Pa.getPort(), "./logs/Tor/cA");
            Thread threadA = new Thread(alice);
            threadA.start();

            //Perimenei 10 second
            countdown.await(5, TimeUnit.SECONDS);

            //Dimiourgia tou Client Bob kai sundesi tou me ton Proxy me to HostName pou pire apo to Tor diktuo sto port 5060
            SIP_TorClient bob = new SIP_TorClient(Pb.getHostName(), Pb.getPort(), "./logs/Tor/cB");
            Thread threadB = new Thread(bob);
            threadB.start();

            //O Bob stelnei REGISTER ston Proxy tou gia ti dieuthunsi tou
            System.out.println(ColorPrint.ANSI_YELLOW + "\n---------------BOB REGISTRATION---------------" + ColorPrint.ANSI_RESET);
            bob.doREGISTER("bob@" + Pb.getHostName());
            System.out.println(ColorPrint.ANSI_YELLOW + "----------------------------------------------" + ColorPrint.ANSI_RESET);

            //Perimenei 10 second
            countdown.await(5, TimeUnit.SECONDS);

            //H Alice stelnei etoima invite pros ton Bob mesw twn Proxies
            System.out.println(ColorPrint.ANSI_YELLOW + "\n---------------ALICE INVITE BOB---------------" + ColorPrint.ANSI_RESET);
            alice.doINVITE("alice@" + Pa.getHostName(), "bob@" + Pb.getHostName());
            System.out.println(ColorPrint.ANSI_YELLOW + "----------------------------------------------" + ColorPrint.ANSI_RESET);

        } catch (NotBoundException | IOException | InterruptedException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }
}
