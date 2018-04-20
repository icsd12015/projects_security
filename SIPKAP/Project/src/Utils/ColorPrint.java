package Utils;

import java.text.SimpleDateFormat;
import java.util.Date;
/**
 *
 * @author icsd12015
 */
public class ColorPrint {

    private static final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");

    public static void print (String msg, String color) {
        System.out.print(ANSI_YELLOW + "[" + sdf.format(new Date()) + "] " + ANSI_RESET);
        System.out.println(color + msg + ANSI_RESET);
    }

    public static void print (String msg, String color, SimpleDateFormat sdf) {
        System.out.print(ANSI_YELLOW + "[" + sdf.format(new Date()) + "] " + ANSI_RESET);
        System.out.println(color + msg + ANSI_RESET);
    }

    //Η μεταβλητες που χρησιμοποιω για την εμφανιση των χρωματων στην κονσολα
    //(τα πηρα και αυτα απο μια παλια εργασια στη Java)
    // <editor-fold defaultstate="collapsed" desc="Colors Variables">
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    // </editor-fold>

}
