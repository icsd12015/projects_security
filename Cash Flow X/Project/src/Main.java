
import // <editor-fold defaultstate="collapsed">  
        java.awt.Color;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.plaf.ColorUIResource;

public class Main {

    public static final String MAIN_DIR_PATH = "data";

    public static final String DIGESTS_FILE_PATH = MAIN_DIR_PATH + "/digests.data";
    public static final String APP_PUBLIC_KEY_FILE_PATH = MAIN_DIR_PATH + "/public.key";

    public static final String USER_FILES_DIR_PATH = MAIN_DIR_PATH + "/user_files";

    //Κωδικες Σφαλματων
    public static final int USERNAME_EXISTS = 1;
    public static final int CORRUPTED_KEY_FILE = 2;
    public static final int CORRUPTED_DIGESTS_FILE = 3;
    public static final int ENCRYPTION_ERROR = 4;
    public static final int ILLEGAL_USERNAME = 5;
    public static final int ILLEGAL_PASSWORD = 6;
    public static final int UNKNOWN_ERROR = 7;

    public static final int USER_NOT_EXISTS = 1;
    public static final int WRONG_PASSWORD = 2;

    public static final int CORRUPTED_DATA_FILES = 1;

    public static final int USER_FILES_INFRIGMENT = 10;

    private static final String usernameREGEX
            = "^\\w(?:\\w*(?:[.-]\\w+)?)*(?<=^.{4,22})$";

    /**
     * Στην αρχη χρησιμοποιησα regex kai για το password αλλα τελικα το κανα σε
     * μεθοδο για καλυτερη ασφαλεια αλλαξα το τροπο υλοποιησης και τωρα δεν
     * αποθηκευεται ποτε ο κωδικος μεσα σε String (δηλαδη στη μνημη)*
     */
//    private static final String passwordREGEX
//            = "^(?=.*\\d)(?=.*[\\[\\]\\^\\$\\.\\|\\?\\*\\+\\(\\)\\\\~`\\!@#%&\\-_+={}'\"\"<>:;, ])(?=.*[a-z])(?=.*[A-Z]).{8,32}$";
    public static final String separator = ":=:";

    private static UserInfo currentUserInfo;

    private static ArrayList<TransactionEntry> currentUserEntries = new ArrayList<>();

    //Μεθοδος για την εγγραφη των νεων χρηστων
    public static int register(String name, String username, char[] password) {
        if (!username.matches(usernameREGEX)) { //Ελγχος για σωστη μορφη username
            return ILLEGAL_USERNAME;
        }
        if (!passwordStrengthCheck(password)) { //Ελεγχος και για σωστη μορφη κωδικου
            return ILLEGAL_PASSWORD;
        }
        try {
            if (getUserInfo(username) == null) { //Ελεγχος αν υπαρχει το username

                //Δημιουργια salts
                byte[] salt = SHA256.generateSalt();
                String saltEncoded = Base64.getEncoder().encodeToString(salt);

                //Δημιουργια συνοψης με salts
                byte[] hash = SHA256.HashWithSalt(toBytes(password), salt);

                //Ασσυμετρη κρυπτογραφηση συνοψης και μετατροπη σε Base64 String για αποθηκευση σε αρχειο
                String encryptedHashEncoded = Base64.getEncoder().encodeToString(
                        RSA2048.encrypt(hash, RSA2048.constructPublicKey(AppKeyPair.getPublic())));

                //Δημιουργια τυχαιου συμμετρικου κλειδιου για τον χρηστη και μετατροπη σε Base64 String για αποθηκευση σε αρχειο
                String randomKeyEncoded = Base64.getEncoder().encodeToString(AES256.getRandomKey().getEncoded());

                //Αποθηκευση στο αρχειο με τις συνοψεις
                appendContentToFile(name + separator + username + separator + saltEncoded
                        + separator + encryptedHashEncoded + separator + randomKeyEncoded + "\n",
                        new File(DIGESTS_FILE_PATH));

                return 0;
            } else {
                return USERNAME_EXISTS;
            }
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            return CORRUPTED_KEY_FILE;
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (IOException ex) {
            ex.printStackTrace();
            return CORRUPTED_DIGESTS_FILE;
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace();
            return CORRUPTED_KEY_FILE;
        } catch (Exception ex) {
            ex.printStackTrace();
            return UNKNOWN_ERROR;
        }

    }

    //Μεθοδος για Συνδεση Χρηστη
    public static int login(String username, char[] password) {
        try {
            currentUserInfo = getUserInfo(username);
            if (!(currentUserInfo == null)) { //Ελεγχος αν υπαρχει το username
                //Παιρνω τα αποθηκευμενα salt και τη κρυπτογραφημενη συνοψη
                String encodedSalt = currentUserInfo.getSaltEncoded();
                String digestEncoded = currentUserInfo.getEncryptedDigestEncoded();

                //Μετατροπη και παλι σε byte array
                byte[] salt = Base64.getDecoder().decode(encodedSalt);
                byte[] hash = SHA256.HashWithSalt(toBytes(password), salt);

                //Ασυμμετρη αποκωδικοποιηση συνοψης
                byte[] decryptedHash = RSA2048.decrypt(
                        Base64.getDecoder().decode(digestEncoded),
                        RSA2048.constructPrivateKey(AppKeyPair.getPrivate()));

                //Συγκριση των συνοψεων για επιβεβαιωση
                if (Arrays.equals(hash, decryptedHash)) {
                    return 0;
                } else {
                    return WRONG_PASSWORD;
                }
            } else {
                return USER_NOT_EXISTS;
            }
        } catch (IOException ex) {
            ex.printStackTrace();
            return CORRUPTED_DIGESTS_FILE;
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            return CORRUPTED_DIGESTS_FILE;
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (InvalidKeySpecException ex) {
            ex.printStackTrace();
            return CORRUPTED_DIGESTS_FILE;
        } catch (Exception ex) {
            ex.printStackTrace();
            return UNKNOWN_ERROR;
        }
    }

    //Μεθοδος για αποθηκευση νεας λογιστικης εγγραφης στο καταλληλο αρχειο
    public static int saveNewEntry(TransactionEntry entry) {
        String user_dir = USER_FILES_DIR_PATH + "/" + currentUserInfo.getUname();
        File udir = new File(user_dir);
        if (!(udir.exists() && udir.isDirectory())) {
            udir.mkdir();
        }

        try {
            //Συμμετρικη κωδικοποιηση με το κλειδι του χρηστη
            String encryptedEntry = AES256.Encrypt(entry.getId() + separator + entry.getDate()
                    + separator + entry.getAmmount() + separator + entry.getDescription(),
                    AES256.getKeyFromBytes(Base64.getDecoder().decode(currentUserInfo.getKeyEncoded()))) + "\n";

            //Αποθηκευση στο καταλληλο αρχειο (αναλογα το ειδος της συνναλαγης)
            if (entry.getType() == TransactionEntry.INCOME) {
                File user_income_file = new File(udir.getPath() + "/" + "income.data");
                appendContentToFile(encryptedEntry, user_income_file);
            } else {
                File user_outcome_file = new File(udir.getPath() + "/" + "outcome.data");
                appendContentToFile(encryptedEntry, user_outcome_file);
            }
            //Προσθηκη στο ArrayList με τις αλλες εγγραφες
            currentUserEntries.add(entry);
            return 0;
        } catch (IOException ex) {
            ex.printStackTrace();
            return CORRUPTED_DATA_FILES;
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            return CORRUPTED_DATA_FILES;
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (Exception ex) {
            ex.printStackTrace();
            return UNKNOWN_ERROR;
        }
    }

    //Μεθοδος για την αντικατασταση μιας εγγραφης μετα απο αλλαγη των στοιχειων της και αποθηκευση 
    public static int replaceEntryAndSave(TransactionEntry entry) {

        //Αντικατασταση της εγγραφης
        for (int i = 0; i < currentUserEntries.size(); i++) {
            if (currentUserEntries.get(i).getId().equals(entry.getId())) {
                currentUserEntries.remove(i);
                currentUserEntries.add(i, entry);
            }
        }

        String user_dir = USER_FILES_DIR_PATH + "/" + currentUserInfo.getUname();
        File user_income_file = new File(user_dir + "/" + "income.data");
        File user_outcome_file = new File(user_dir + "/" + "outcome.data");
        //Αποθηκευση παλι των εγγραφων στο αρχειο
        try {
            FileWriter fw;
            if (entry.getType() == TransactionEntry.INCOME) {
                fw = new FileWriter(user_income_file);
            } else {
                fw = new FileWriter(user_outcome_file);
            }
            BufferedWriter buff = new BufferedWriter(fw);

            for (TransactionEntry e : currentUserEntries) {
                if (e.getType() == entry.getType()) {
                    String encryptedEntry = AES256.Encrypt(e.getId() + separator + e.getDate()
                            + separator + e.getAmmount() + separator + e.getDescription(),
                            AES256.getKeyFromBytes(Base64.getDecoder().decode(currentUserInfo.getKeyEncoded()))) + "\n";

                    buff.write(encryptedEntry);
                }
            }
            buff.close();
            fw.close();
            return 0;
        } catch (IOException ex) {
            ex.printStackTrace();
            return CORRUPTED_DATA_FILES;
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            return CORRUPTED_DATA_FILES;
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (Exception ex) {
            ex.printStackTrace();
            return UNKNOWN_ERROR;
        }
    }

    //Μεθοδος για τη φορτωση των εγγραφων του χρηστη απο τα αρχεια (γινεται στην αρχη)
    public static int getCurrentUserEntries() {
        String user_dir = USER_FILES_DIR_PATH + "/" + currentUserInfo.getUname();
        File user_income_file = new File(user_dir + "/" + "income.data");
        File user_outcome_file = new File(user_dir + "/" + "outcome.data");
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(
                    new FileInputStream(user_income_file)));

            String encryptedEntry;

            //Καθε γραμμη ειναι μια εγγραφη, αποκωδικοποιειται και επειτα τη σπαω σε κομματια (με το separator που ορισα)
            //παιρνω τα στοιχεια της, τη δημιουργω και τη βαζω στη λιστα με τις εγγραφες του χρηστη
            //Αυτο γινεται κια στα δυο αρχεια του χρηστη
            while ((encryptedEntry = br.readLine()) != null) {
                String decryptedEntryStr = AES256.Decrypt(encryptedEntry,
                        AES256.getKeyFromBytes(Base64.getDecoder().decode(currentUserInfo.getKeyEncoded())));
                String[] entryDetails = decryptedEntryStr.split(separator);
                TransactionEntry entry = new TransactionEntry(entryDetails[0], entryDetails[1],
                        entryDetails[2], entryDetails[3], TransactionEntry.INCOME);
                currentUserEntries.add(entry);
            }
            br.close();

            br = new BufferedReader(new InputStreamReader(
                    new FileInputStream(user_outcome_file)));

            while ((encryptedEntry = br.readLine()) != null) {
                String decryptedEntryStr = AES256.Decrypt(encryptedEntry,
                        AES256.getKeyFromBytes(Base64.getDecoder().decode(currentUserInfo.getKeyEncoded())));
                String[] entryDetails = decryptedEntryStr.split(separator);
                TransactionEntry entry = new TransactionEntry(entryDetails[0], entryDetails[1],
                        entryDetails[2], entryDetails[3], TransactionEntry.OUTCOME);
                currentUserEntries.add(entry);
            }
            return 0;
        } catch (FileNotFoundException ex) {
            return 0;
        } catch (IOException ex) {
            ex.printStackTrace();
            return CORRUPTED_DATA_FILES;
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            return CORRUPTED_DATA_FILES;
        } catch (InvalidAlgorithmParameterException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
            return ENCRYPTION_ERROR;
        } catch (Exception ex) {
            ex.printStackTrace();
            return UNKNOWN_ERROR;
        }

    }

    //Μεθοδος για Επιστροφη λιστας συνναλαγων οι οποιες εγιναν σε μια συγκεκριμενη ημερομηνια

    public static ArrayList<TransactionEntry> getEntriesWithSelectedDate(String selectedDate) {
        ArrayList<TransactionEntry> entries = new ArrayList<>();

        for (TransactionEntry e : currentUserEntries) {
            if (e.getDate().equals(selectedDate)) {
                entries.add(e);
            }
        }

        return entries;
    }

    //Μεθοδος για επιστροφη συνναλαγης βαση του κωδικου της

    public static TransactionEntry getEntryByID(String id) {
        for (TransactionEntry e : currentUserEntries) {
            if (e.getId().equals(id)) {
                return e;
            }
        }
        return null;
    }

    //Μεθοδος για επιστροφη λιστας με τους μηνες οι οποιοι εχουν συνναλαγες (η δευτερη λιστα ειναι για
    //να κρατασει εναν αριθμο για τον μηνα και ενα για τη χρονια του μηνα. Και επειδη ειναι και αυτο 
    //ειναι λιστα μπορω να χρησιμοποιησω την μεθοδο contains που με γλυτωσε απο κοπο
    public static ArrayList<ArrayList<Integer>> getMonthsWithEntries() {
        ArrayList<ArrayList<Integer>> months = new ArrayList<>();
        java.text.SimpleDateFormat formatter = new java.text.SimpleDateFormat(GUI.dateFormat);
        for (TransactionEntry entry : currentUserEntries) {
            try {
                java.util.Date d = formatter.parse(entry.getDate());
                ArrayList<Integer> temp = new ArrayList<>(Arrays.asList(
                        Integer.parseInt(new java.text.SimpleDateFormat("MM").format(d)) - 1,
                        Integer.parseInt(new java.text.SimpleDateFormat("yyyy").format(d))));
                if (!months.contains(temp)) {
                    months.add(temp);
                }
            } catch (ParseException ex) {
                ex.printStackTrace();
            }
        }
        return months;
    }

    //Μεθοδοσ γι την επιστροφη λιστας με εγγραφες που εχουν γινει σε ενα συγκεκριμενο μηνα
    public static ArrayList<TransactionEntry> getEntriesWithSelectedMonth(String selectedMonth) {
        ArrayList<TransactionEntry> entries = new ArrayList<>();

        for (TransactionEntry e : currentUserEntries) {
            java.util.Date entryDate = null;
            try {
                entryDate = new java.text.SimpleDateFormat(GUI.dateFormat).parse(e.getDate());
            } catch (ParseException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
            if (new java.text.SimpleDateFormat(GUI.monthYearFormat).format(entryDate)
                    .equals(selectedMonth)) {
                entries.add(e);
            }
        }

        return entries;
    }

    //Η main στην αρχη αλλαζει την εμφανιση των γραφικων της java. Προσοχη χρειαζεται να προσθεσετε τη βιβλιοθηκη που υπαρχει
    //στον φακελο lib του project αλλιως τα γραφικα δε θα φαινονται καλα
    //Επισης φτιαχνει τους απαραιτητους φακελους αν δεν υπαρχουν και καλει τα γραφικα

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel("com.jtattoo.plaf.hifi.HiFiLookAndFeel");
                UIManager.put("ComboBox.selectionBackground", new ColorUIResource(new Color(80, 80, 80)));
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
                System.out.println("JTatto not found.");
                //  System.exit(1);
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            File mdir = new File(MAIN_DIR_PATH);
            if (!(mdir.exists() && mdir.isDirectory())) {
                mdir.mkdir();
            }
            File kdir = new File(USER_FILES_DIR_PATH);
            if (!(kdir.exists() && kdir.isDirectory())) {
                kdir.mkdir();
            }
            File appkeyfile = new File(APP_PUBLIC_KEY_FILE_PATH);
            if (!appkeyfile.exists()) {
                try (PrintStream out = new PrintStream(new FileOutputStream(appkeyfile))) {
                    out.print(AppKeyPair.getPublic());
                } catch (FileNotFoundException ex) {
                    ex.printStackTrace();
                }
            }
            File digestsfile = new File(DIGESTS_FILE_PATH);
            if (!digestsfile.exists()) {
                try {
                    digestsfile.createNewFile();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
            new GUI();
        });
    }

    //Μεθοδος για τον ελεγχο την ασφαλειας του κωδικου (να εχει ενα πεζο ενα κεφαλαιο εναν ειδικο χαρακτηρα 
    //και ενα ψηφιο τουλαχιστον και να ειναι απο 8 εως 32 χαρακτρηρες)

    private static boolean passwordStrengthCheck(char[] pass) {
        boolean special = false, uppercase = false, lowercase = false, digit = false, 
                whitespace = false, illegal = false, length = pass.length > 8 && pass.length < 32;
        for (int i = 0; i < pass.length; i++) {
            if (Character.isUpperCase(pass[i])) {
                uppercase = true;
            } else if (Character.isLowerCase(pass[i])) {
                lowercase = true;
            } else if (Character.isDigit(pass[i])) {
                digit = true;
            } else if (Character.isWhitespace(pass[i])) {
                whitespace = true;
            } else if (!Character.isAlphabetic(i)) {
                special = true;
            } else {
                illegal = true;
            }
        }

        return (special && uppercase && lowercase && length && !whitespace && !illegal);
    }
    
    //Βρισκει τα στοιχεια ενος χρηστη που εχουν αποθηκευτει στο αρχειο των συνοψεων

    private static UserInfo getUserInfo(String username) throws IOException {
        UserInfo user = null;

        FileInputStream fstream = new FileInputStream(DIGESTS_FILE_PATH);
        BufferedReader br = new BufferedReader(new InputStreamReader(fstream));

        String line;

        while ((line = br.readLine()) != null) {
            String[] separated = line.split(separator);
            if (username.equals(separated[2])) {
                user = new UserInfo(separated[0], separated[1], separated[2],
                        separated[3], separated[4], separated[5]);
            }
        }

        br.close();

        return user;
    }

    public static UserInfo getCurrentUserInfo() {
        return currentUserInfo;
    }

    private static void appendContentToFile(String content, File file) throws IOException {
        if (!file.exists()) {
            file.createNewFile();
        }
        FileWriter fw = new FileWriter(file, true);
        BufferedWriter buff = new BufferedWriter(fw);
        buff.write(content);
        buff.close();
        fw.close();
    }
    //μετατροπη πινακα χαρακτηρων σε πινακα byte
    private static byte[] toBytes(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());
        Arrays.fill(charBuffer.array(), '\u0000'); // clear sensitive data
        Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
        return bytes;
    }
}
