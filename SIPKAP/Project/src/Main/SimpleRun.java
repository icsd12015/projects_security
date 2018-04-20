package Main;


import Registrar.DatabaseServer;
import UAClient.SIP_Client;
import UAServer.SIP_Proxy;
import Utils.ColorPrint;
import java.io.IOException;
import java.rmi.NotBoundException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 *
 * @author icsd12015
 */
public class SimpleRun extends Thread {

    private CountDownLatch countdown;

    public static void main (String[] args) {
        new SimpleRun().start();
    }

    @Override
    public void run () {
        countdown = new CountDownLatch(1);
        try {

            //Dimiourgia twn duo Database Servers me ta stoixeia twn Clients
            DatabaseServer Ra = new DatabaseServer("SIP_RegistrarA", 7080, "./db/clientsA.db");
            DatabaseServer Rb = new DatabaseServer("SIP_RegistrarB", 7080, "./db/clientsB.db");

            //Dimiourgia twn duo Proxy Servers sta ports 7060 kai 7061
            SIP_Proxy Pa = new SIP_Proxy("localhost", 7060, 10, Ra.getURL());
            SIP_Proxy Pb = new SIP_Proxy("localhost", 7061, 10, Rb.getURL());

            //Enarksi twn Proxies se threads
            Thread PaThread = new Thread(Pa);
            PaThread.start();

            Thread PbThread = new Thread(Pb);
            PbThread.start();

            //Perimenei 1 second
            countdown.await(1, TimeUnit.SECONDS);

            //Dimiourgia tou Client Alice kai sundesi tou me ton Proxy sto port 7060 apo to port 5060
            SIP_Client alice = new SIP_Client("localhost", 7060, 5060);
            Thread threadA = new Thread(alice);
            threadA.start();

            //Perimenei 1 second
            countdown.await(1, TimeUnit.SECONDS);

            //Dimiourgia tou Client Bob kai sundesi tou me ton Proxy sto port 7061 apo to port 5061
            SIP_Client bob = new SIP_Client("localhost", 7061, 5061);
            Thread threadB = new Thread(bob);
            threadB.start();

            //Perimenei 1 second
            countdown.await(1, TimeUnit.SECONDS);

            //O Bob stelnei REGISTER ston Proxy tou gia ti dieuthunsi tou
            System.out.println(ColorPrint.ANSI_YELLOW + "\n---------------BOB REGISTRATION---------------" + ColorPrint.ANSI_RESET);
            bob.doREGISTER("bob@127.0.0.1");
            System.out.println(ColorPrint.ANSI_YELLOW + "----------------------------------------------" + ColorPrint.ANSI_RESET);

            //Perimenei 2 seconds
            countdown.await(2, TimeUnit.SECONDS);

            //H Alice stelnei etoima invite pros ton Bob mesw twn Proxies
            System.out.println(ColorPrint.ANSI_YELLOW + "\n---------------ALICE INVITE BOB---------------" + ColorPrint.ANSI_RESET);
            alice.doINVITE("alice@127.0.0.1", "bob@127.0.0.1");
            System.out.println(ColorPrint.ANSI_YELLOW + "----------------------------------------------" + ColorPrint.ANSI_RESET);
        } catch (NotBoundException | IOException | InterruptedException ex) {
            ex.printStackTrace();
            System.exit(1);
        }
    }
}
