
import // <editor-fold defaultstate="collapsed">  
        java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontFormatException;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.imageio.ImageIO;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingConstants;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.JTextComponent;
import javax.swing.text.PlainDocument;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

public final class GUI extends JFrame {

    private final String appiconpath = "resources\\images\\icon.png";
    private final String backgroundpath = "resources\\images\\back.png";
    private final String newentryiconpath = "resources/images/add_entry.png";
    private final String editentriesiconpath = "resources/images/edit_entries.png";
    private final String reportsiconpath = "resources/images/create_reports.png";
    private final String caliconpath = "resources/images/calendar.png";
    //Stin arxi eixa valei alli grammatoseira alla telika to evgala
  //  private final String fontpath = "resources\\fonts\\BOOKOSB.ttf"; 

    private final int cwidth = 200, cheight = 25;

    JFrame me = this;

    private JComponent pane;

    private JTextField fnameF, lnameF, usernameF;
    private JPasswordField passwordF, password2F;

    private JTextField ammountF, dateF,
            ammount2F, date2F, selectDateF,
            selectMonthF, sumF;
    private JTextPane entriesPane;
    private JButton calB, saveB,
            cal2B, save2B;
    private JScrollPane descriptionS,
            description2S;
    private JTextArea descriptionT,
            description2T;
    private JComboBox<String> typeC,
            type2C;

    private JComboBox<String> selectIDC;

    public static final String dateFormat = "dd/MM/yyyy";
    public static final String monthYearFormat = "MM/yyyy";

    private String ammountBackup, descriptionBackup, dateBackup, typeBackup;
    int idCindexBackup, previousTab = -1;

    private static boolean ammountChanged = false, descriptionChanged = false, dateChanged = false, typeChanged = false,
            approved = true;

    private final AbstractAction loginBLoginGUI = // <editor-fold defaultstate="collapsed" desc="Login Button Actions (Login)">  
            new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    boolean error = false;
                    usernameF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                    passwordF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                    if (usernameF.getText().isEmpty()) {
                        usernameF.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (new String(passwordF.getPassword()).isEmpty()) {
                        passwordF.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (!error) {
                        int flag = Main.login(usernameF.getText(), passwordF.getPassword());
                        switch (flag) {
                            case Main.USER_NOT_EXISTS:
                                JOptionPane.showMessageDialog(me,
                                        "The username and the password you entered do not match.\nPlease check out the entries and try again.",
                                        "Login Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.WRONG_PASSWORD:
                                JOptionPane.showMessageDialog(me,
                                        "The username and the password you entered do not match.\nPlease check out the entries and try again.",
                                        "Login Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.CORRUPTED_DIGESTS_FILE:
                                JOptionPane.showMessageDialog(me,
                                        "Error reading from file.\nFile digests.data might be corrupted.",
                                        "Login Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.ENCRYPTION_ERROR:
                                JOptionPane.showMessageDialog(me,
                                        "Encryption error.\nJCE library may be missing.",
                                        "Login Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.UNKNOWN_ERROR:
                                JOptionPane.showMessageDialog(me,
                                        "Unknown error occured.\nYour data files might be corrupted."
                                        + "\nYour save data could not be loaded",
                                        "Login Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            default:
                                JOptionPane.showMessageDialog(me,
                                        "Welcome " + Main.getCurrentUserInfo().getFname(),
                                        "Login Successfull",
                                        JOptionPane.PLAIN_MESSAGE);

                                flag = Main.getCurrentUserEntries();
                                switch (flag) {
                                    case Main.CORRUPTED_DATA_FILES:
                                        JOptionPane.showMessageDialog(me,
                                                "Encryption error.\nYour data files might be corrupted."
                                                + "\nYour save data could not be loaded",
                                                "Data Load Error",
                                                JOptionPane.ERROR_MESSAGE);
                                        break;
                                    case Main.ENCRYPTION_ERROR:
                                        JOptionPane.showMessageDialog(me,
                                                "Encryption error.\nJCE library might be missing."
                                                + "\nYour save data could not be loaded",
                                                "Data Load Error",
                                                JOptionPane.ERROR_MESSAGE);
                                        break;
                                    case Main.UNKNOWN_ERROR:
                                        JOptionPane.showMessageDialog(me,
                                                "Unknown error occured.\nYour data files might be corrupted."
                                                + "\nYour save data could not be loaded",
                                                "Data Load Error",
                                                JOptionPane.ERROR_MESSAGE);
                                        break;
                                    default:

                                }
                                if (new File(Main.USER_FILES_DIR_PATH + "/" + usernameF.getText() + "/" + "signature.sign").exists()) {
                                    flag = IntegrityMechanism.verifyUserFiles(usernameF.getText(), "signature.sign");
                                    switch (flag) {
                                        case Main.USER_FILES_INFRIGMENT:
                                            JOptionPane.showMessageDialog(me,
                                                    "Attention!\nYour data files have been ifrigmented!"
                                                    + "\nSomeone tried to steal your data!",
                                                    "Signature Verification Failed!",
                                                    JOptionPane.INFORMATION_MESSAGE);
                                            break;
                                        case Main.CORRUPTED_DATA_FILES:
                                            JOptionPane.showMessageDialog(me,
                                                    "Encryption error.\nYour data files might be corrupted."
                                                    + "\nYour save data could not be loaded",
                                                    "Signature Verification Failed!",
                                                    JOptionPane.ERROR_MESSAGE);
                                            break;
                                        case Main.ENCRYPTION_ERROR:
                                            JOptionPane.showMessageDialog(me,
                                                    "Encryption error.\nJCE library might be missing."
                                                    + "\nYour save data could not be loaded",
                                                    "Signature Verification Failed!",
                                                    JOptionPane.ERROR_MESSAGE);
                                            break;
                                        default:
                                            JOptionPane.showMessageDialog(me,
                                                    "Signature verification of your files completed successfully."
                                                    + "Your data is secured.",
                                                    "Signature Verification Success!",
                                                    JOptionPane.INFORMATION_MESSAGE);
                                    }
                                }
                                CreateMainGUI();
                        }

                    }
                }
            };// </editor-fold>
    private final AbstractAction registerBLoginGUI = // <editor-fold defaultstate="collapsed" desc="Register Button Actions (Login)">  
            new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    CreateRegisterGUI(usernameF.getText());
                }
            };// </editor-fold>
    private final AbstractAction loginBRegisterGUI = // <editor-fold defaultstate="collapsed" desc="Login Button Actions (Registration)">  
            new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {

                    if (!(fnameF.getText().isEmpty() && lnameF.getText().isEmpty() && usernameF.getText().isEmpty()
                    && passwordF.getPassword().length == 0 && password2F.getPassword().length == 0)) {
                        int opt = JOptionPane.showOptionDialog(me,
                                "Are you sure you want to cancel registration",
                                "Cornfirm to return",
                                JOptionPane.YES_NO_OPTION,
                                JOptionPane.QUESTION_MESSAGE, null, null, null
                        );
                        if (opt == 0) {
                            CreateLoginGUI("");
                        }
                    } else {
                        CreateLoginGUI("");
                    }
                }
            };// </editor-fold>
    private final AbstractAction registerBRegisterGUI = // <editor-fold defaultstate="collapsed" desc="Register Button Actions (Registration)">  
            new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    fnameF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                    lnameF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                    usernameF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                    passwordF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                    password2F.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

                    boolean error = false;

                    if (fnameF.getText().isEmpty()) {
                        fnameF.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (lnameF.getText().isEmpty()) {
                        lnameF.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (usernameF.getText().isEmpty()) {
                        usernameF.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (passwordF.getPassword().length == 0) {
                        passwordF.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (password2F.getPassword().length == 0) {
                        password2F.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (!Arrays.equals(passwordF.getPassword(), password2F.getPassword())) {
                        password2F.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        passwordF.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (!error) {
                        int flag = Main.register(fnameF.getText() + Main.separator + lnameF.getText(),
                                usernameF.getText(), passwordF.getPassword());
                        switch (flag) {
                            case Main.ILLEGAL_USERNAME:
                                JOptionPane.showMessageDialog(me,
                                        "Username must not contain illegal characters\nand must must be at lest 8 characters long.",
                                        "Illegal username",
                                        JOptionPane.ERROR_MESSAGE);
                                usernameF.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                                break;
                            case Main.ILLEGAL_PASSWORD:
                                JOptionPane.showMessageDialog(me,
                                        "Password must contain at least one special, uppercase and lowercase character\n"
                                        + "and must have length from 8 to 32 characters.",
                                        "Weak password",
                                        JOptionPane.ERROR_MESSAGE);
                                passwordF.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                                break;
                            case Main.CORRUPTED_KEY_FILE:
                                JOptionPane.showMessageDialog(me,
                                        "Encryption error.\nFile public.key might be corrupted.",
                                        "Registration Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.ENCRYPTION_ERROR:
                                JOptionPane.showMessageDialog(me,
                                        "Encryption error.\nJCE library might be missing.",
                                        "Registration Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.CORRUPTED_DIGESTS_FILE:
                                JOptionPane.showMessageDialog(me,
                                        "Error reading from file.\nFile digests.data might be corrupted.",
                                        "Registration Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.USERNAME_EXISTS:
                                JOptionPane.showMessageDialog(me,
                                        "Username already exists.\nTry using another username.",
                                        "Registration Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.UNKNOWN_ERROR:
                                JOptionPane.showMessageDialog(me,
                                        "Unknown error occured.\nYour data files might be corrupted.",
                                        "Registration Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            default:
                                JOptionPane.showMessageDialog(me,
                                        "Your account has been registered successfully.\nYou can now login using your credentials.",
                                        "Registration Successfull",
                                        JOptionPane.INFORMATION_MESSAGE);
                                CreateLoginGUI(usernameF.getText());
                        }
                    }

                }
            };// </editor-fold>
    private final AbstractAction saveBNewEntryTabGUI = // <editor-fold defaultstate="collapsed" desc="Save Button Actions (New Entry Tab)">  
            new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    ammountF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
                    descriptionS.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                    dateF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
                    calB.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
                    typeC.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

                    boolean error = false;

                    if (ammountF.getText().isEmpty()
                    || ammountF.getText().equals("0.00")) {
                        ammountF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.RED));
                        error = true;
                    }
                    if (descriptionT.getText().isEmpty()) {
                        descriptionS.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (dateF.getText().isEmpty()) {
                        dateF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.RED));
                        calB.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.RED));
                        error = true;
                    }
                    if (typeC.getSelectedIndex() == 0) {
                        typeC.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.RED));
                        error = true;
                    }
                    if (!error) {
                        TransactionEntry entry = new TransactionEntry(dateF.getText(),
                                ammountF.getText(), descriptionT.getText(),
                                typeC.getSelectedIndex());

                        int flag = Main.saveNewEntry(entry);

                        switch (flag) {
                            case Main.CORRUPTED_DATA_FILES:
                                JOptionPane.showMessageDialog(me,
                                        "Encryption error.\nYour data files might be corrupted.",
                                        "Saving Transaction Entry Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.ENCRYPTION_ERROR:
                                JOptionPane.showMessageDialog(me,
                                        "Encryption error.\nJCE library might be missing.",
                                        "Saving Transaction Entry Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.CORRUPTED_DIGESTS_FILE:
                                JOptionPane.showMessageDialog(me,
                                        "Error reading from file.\nFile digests.data might be corrupted.",
                                        "Saving Transaction Entry Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            case Main.UNKNOWN_ERROR:
                                JOptionPane.showMessageDialog(me,
                                        "Unknown error occured.\nYour data files might be corrupted.",
                                        "Saving Transaction Entry Failed",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            default:
                                JOptionPane.showMessageDialog(me,
                                        "Your transaction entry added successfully.",
                                        "Transaction Entry Created",
                                        JOptionPane.INFORMATION_MESSAGE);
                                ammountF.setText("");
                                descriptionT.setText("");
                                dateF.setText("");
                                typeC.setSelectedIndex(0);
                        }
                    }
                }
            };// </editor-fold>
    private final AbstractAction cancelBNewEntryTabGUI = // <editor-fold defaultstate="collapsed" desc="Cancel Button Actions (New Entry Tab)">  
            new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {

                    int opt = JOptionPane.showOptionDialog(me,
                            "All fields will be cleared!\nAre you sure?",
                            "Confirm to discard",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.QUESTION_MESSAGE, null, null, null
                    );
                    if (opt == 0) {
                        ammountF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
                        descriptionS.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                        dateF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
                        calB.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
                        typeC.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

                        ammountF.setText("");
                        descriptionT.setText("");
                        dateF.setText("");
                        typeC.setSelectedIndex(0);
                    }
                }
            };// </editor-fold>
    private final AbstractAction saveBEditEntriesTabGUI = // <editor-fold defaultstate="collapsed" desc="Save Button Actions (Edit Entries Tab)">  
            new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
                    description2S.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                    date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
                    cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
                    type2C.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

                    boolean error = false;

                    if (ammount2F.getText().isEmpty()
                    || ammount2F.getText().equals("0.00")) {
                        ammountF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.RED));
                        error = true;
                    }
                    if (description2T.getText().isEmpty()) {
                        descriptionS.setBorder(BorderFactory.createLineBorder(Color.RED, 1));
                        error = true;
                    }
                    if (date2F.getText().isEmpty()) {
                        date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.RED));
                        cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.RED));
                        error = true;
                    }
                    if (type2C.getSelectedIndex() == 0) {
                        type2C.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.RED));
                        error = true;
                    }
                    if (!error) {
                        if (!(ammountChanged || descriptionChanged || dateChanged || typeChanged)) {
                            JOptionPane.showMessageDialog(me,
                                    "It appears that you have made no changes on the entry details.\n"
                                    + "Please change something first.",
                                    "Nothing to save",
                                    JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            TransactionEntry entry = new TransactionEntry(((String) selectIDC.getSelectedItem()).replaceAll("#", ""),
                                    date2F.getText(), ammount2F.getText(), description2T.getText(), type2C.getSelectedIndex());

                            int flag = Main.replaceEntryAndSave(entry);

                            switch (flag) {
                                case Main.CORRUPTED_DATA_FILES:
                                    JOptionPane.showMessageDialog(me,
                                            "Encryption error.\nYour data files might be corrupted.",
                                            "Saving Transaction Entry Failed",
                                            JOptionPane.ERROR_MESSAGE);
                                    break;
                                case Main.ENCRYPTION_ERROR:
                                    JOptionPane.showMessageDialog(me,
                                            "Encryption error.\nJCE library might be missing.",
                                            "Saving Transaction Entry Failed",
                                            JOptionPane.ERROR_MESSAGE);
                                    break;
                                case Main.CORRUPTED_DIGESTS_FILE:
                                    JOptionPane.showMessageDialog(me,
                                            "Error reading from file.\nFile digests.data might be corrupted.",
                                            "Saving Transaction Entry Failed",
                                            JOptionPane.ERROR_MESSAGE);
                                    break;
                                case Main.UNKNOWN_ERROR:
                                    JOptionPane.showMessageDialog(me,
                                            "Unknown error occured.\nYour data files might be corrupted.",
                                            "Saving Transaction Entry Failed",
                                            JOptionPane.ERROR_MESSAGE);
                                    break;
                                default:
                                    JOptionPane.showMessageDialog(me,
                                            "The changes in transaction entry have been saved successfully.",
                                            "Transaction Entry Details Changed",
                                            JOptionPane.INFORMATION_MESSAGE);
                                    setSize(350, 238);
                                    selectDateF.setText("");
                                    selectIDC.removeAllItems();
                                    selectIDC.addItem("...");
                                    selectIDC.setEnabled(false);
                                    ammountF.setText("");
                                    descriptionT.setText("");
                                    dateF.setText("");
                                    typeC.setSelectedIndex(0);
                                    ammountChanged = false;
                                    descriptionChanged = false;
                                    dateChanged = false;
                                    typeChanged = false;
                                    ammountBackup = "";
                                    descriptionBackup = "";
                                    dateBackup = "";
                                    typeBackup = "";
                                    updateSelectIDC();
                            }
                        }
                    }
                }
            };// </editor-fold>
    private final AbstractAction restoreBEditEntriesTabGUI = // <editor-fold defaultstate="collapsed" desc="Cancel Button Actions (Edit Entries Tab)">  
            new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if (ammountChanged || descriptionChanged || dateChanged || typeChanged) {

                        int opt = JOptionPane.showOptionDialog(me,
                                "All fields will be restored!\nAre you sure?",
                                "Confirm to restore",
                                JOptionPane.YES_NO_OPTION,
                                JOptionPane.QUESTION_MESSAGE, null, null, null
                        );
                        if (opt == 0) {
                            ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
                            description2S.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
                            date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
                            cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
                            type2C.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

                            ammount2F.setText(ammountBackup);
                            description2T.setText(descriptionBackup);
                            date2F.setText(dateBackup);
                            type2C.setSelectedItem(typeBackup);
                        }
                    }
                }
            };// </editor-fold>

    public GUI() {
        CreateLoginGUI("");
        setTitle("Cash Flow X");
        setIcon(appiconpath);
        setResizable(false);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLocation(getLocation().x, getLocation().y - 200);
        setVisible(true);
        
        addWindowListener(new WindowListener() {
            @Override
            public void windowOpened(WindowEvent e) {
            }

            @Override
            public void windowClosing(WindowEvent e) {
                int flag = IntegrityMechanism.signUserFiles(usernameF.getText(), "signature.sign");
                switch (flag) {
                    case Main.CORRUPTED_DATA_FILES:
                        JOptionPane.showMessageDialog(me,
                                "Encryption error.\nYour data files might be corrupted."
                                + "\nYour save data could not be loaded",
                                "Signature Verification Failed!",
                                JOptionPane.ERROR_MESSAGE);
                        break;
                    case Main.ENCRYPTION_ERROR:
                        JOptionPane.showMessageDialog(me,
                                "Encryption error.\nJCE library might be missing."
                                + "\nYour save data could not be loaded",
                                "Signature Verification Failed!",
                                JOptionPane.ERROR_MESSAGE);
                        break;
                    default:
                        JOptionPane.showMessageDialog(me,
                                "Digital signature of your files has been created successfully."
                                + "\nYour data is secured.",
                                "Signature Creation Success!",
                                JOptionPane.INFORMATION_MESSAGE);
                }
            }

            @Override

            public void windowClosed(WindowEvent e) {
            }

            @Override
            public void windowIconified(WindowEvent e) {
            }

            @Override
            public void windowDeiconified(WindowEvent e) {
            }

            @Override
            public void windowActivated(WindowEvent e) {
            }

            @Override
            public void windowDeactivated(WindowEvent e) {
            }
        }
        );
    }

    public void CreateLoginGUI(String uname) {
        // <editor-fold defaultstate="collapsed" desc="Login INIT">  

        int cmarginX = 20;
        int cmarginY = 10;
        int spaceY = 20;

        //getCustomFont(fontpath);

        JLabel usernameL = new JLabel("Username");
        usernameL.setBounds(cmarginX, cmarginY, cwidth, cheight);
//        usernameL.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
//        usernameL.setForeground(new Color(192, 192, 192));

        cmarginY += cheight;

        usernameF = new JTextField(uname);
        usernameF.setBounds(cmarginX, cmarginY, cwidth, cheight);
        usernameF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

        cmarginY += cheight + spaceY;

        JLabel passwordL = new JLabel("Password");
        passwordL.setBounds(cmarginX, cmarginY, cwidth, cheight);
//        passwordL.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
//        passwordL.setForeground(new Color(192, 192, 192));

        cmarginY += cheight;

        passwordF = new JPasswordField();
        passwordF.setBounds(cmarginX, cmarginY, cwidth, cheight);
        passwordF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
//        passwordF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

        cmarginY += cheight + spaceY + 10;

        JButton loginB = new JButton("Login");
        loginB.setFocusPainted(false);
        loginB.setBounds(cmarginX, cmarginY, 90, cheight);
//        loginB.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
        loginB.addActionListener(loginBLoginGUI);
        loginB.getInputMap(javax.swing.JComponent.WHEN_IN_FOCUSED_WINDOW).
                put(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ENTER, 0), "ENTER");
        loginB.getActionMap().put("ENTER", loginBLoginGUI);

        JButton registerB = new JButton("Register");
        registerB.setFocusPainted(false);
        registerB.setBounds(cmarginX + 90 + 20, cmarginY, 90, cheight);
//        registerB.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
        registerB.addActionListener(registerBLoginGUI);

        this.setSize(cmarginX * 2 + cwidth, cmarginY + cheight + 45);
        pane = new JLabel(
                createImageIcon(backgroundpath, this.getWidth(), this.getHeight()));
        this.setContentPane(pane);

        pane.setLayout(null);

        pane.add(usernameL);
        pane.add(usernameF);
        pane.add(passwordL);
        pane.add(passwordF);
        pane.add(loginB);
        pane.add(registerB);
        // </editor-fold>
    }

    public void CreateRegisterGUI(String uname) {
        // <editor-fold defaultstate="collapsed" desc="Registration INIT">  
        int cmarginX = 20;
        int cmarginY = 10;
        int spaceY = 20;

        JLabel fnameL = new JLabel("First Name");
        fnameL.setBounds(cmarginX, cmarginY, cwidth, cheight);
//        fnameL.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
//        fnameL.setForeground(new Color(192, 192, 192));

        cmarginY += cheight;

        fnameF = new JTextField();
        fnameF.setBounds(cmarginX, cmarginY, cwidth, cheight);
        fnameF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
        fnameF.setDocument(new AmmountDocument(32));

        cmarginY += cheight + spaceY;

        JLabel lnameL = new JLabel("Last Name");
        lnameL.setBounds(cmarginX, cmarginY, cwidth, cheight);
//        lnameL.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
//        lnameL.setForeground(new Color(192, 192, 192));

        cmarginY += cheight;

        lnameF = new JTextField();
        lnameF.setBounds(cmarginX, cmarginY, cwidth, cheight);
        lnameF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
        lnameF.setDocument(new AmmountDocument(32));

        cmarginY += cheight + spaceY;

        JLabel usernameL = new JLabel("Username");
        usernameL.setBounds(cmarginX, cmarginY, cwidth, cheight);
//        usernameL.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
//        usernameL.setForeground(new Color(192, 192, 192));

        cmarginY += cheight;

        usernameF = new JTextField();
        usernameF.setBounds(cmarginX, cmarginY, cwidth, cheight);
        usernameF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
        usernameF.setDocument(new AmmountDocument(22));
        usernameF.setText(uname);

        cmarginY += cheight + spaceY;

        JLabel passwordL = new JLabel("Password");
        passwordL.setBounds(cmarginX, cmarginY, cwidth, cheight);
//        passwordL.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
//        passwordL.setForeground(new Color(192, 192, 192));

        cmarginY += cheight;

        passwordF = new JPasswordField();
        passwordF.setBounds(cmarginX, cmarginY, cwidth, cheight);
        passwordF.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
        passwordF.setDocument(new AmmountDocument(32));

        cmarginY += cheight + spaceY;

        JLabel password2L = new JLabel("Confirm Password");
        password2L.setBounds(cmarginX, cmarginY, cwidth, cheight);
//        password2L.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
//        password2L.setForeground(new Color(192, 192, 192));

        cmarginY += cheight;

        password2F = new JPasswordField();
        password2F.setBounds(cmarginX, cmarginY, cwidth, cheight);
        password2F.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
        password2F.setDocument(new AmmountDocument(32));

        cmarginY += cheight + spaceY + 10;

        JButton registerB = new JButton("Register");
        registerB.setFocusPainted(false);
        registerB.setBounds(cmarginX, cmarginY, 90, cheight);
//        registerB.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
        registerB.addActionListener(registerBRegisterGUI);
        registerB.getInputMap(javax.swing.JComponent.WHEN_IN_FOCUSED_WINDOW).
                put(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ENTER, 0), "ENTER");
        registerB.getActionMap().put("ENTER", registerBRegisterGUI);

        JButton loginB = new JButton("Login");
        loginB.setFocusPainted(false);
        loginB.setBounds(cmarginX + 90 + 30, cmarginY, 90, cheight);
//        loginB.setFont(new Font("Bookman Old Style", Font.PLAIN, 15));
        loginB.addActionListener(loginBRegisterGUI);

        this.setSize(cwidth + cmarginX * 2, cmarginY + cheight + 45);
        pane = new JLabel(
                createImageIcon(backgroundpath, this.getWidth(), this.getHeight()));
        this.setContentPane(pane);
        pane.setLayout(null);

        pane.add(fnameL);
        pane.add(fnameF);
        pane.add(lnameL);
        pane.add(lnameF);
        pane.add(usernameL);
        pane.add(usernameF);
        pane.add(passwordL);
        pane.add(passwordF);
        pane.add(password2L);
        pane.add(password2F);
        pane.add(registerB);
        pane.add(loginB);
        // </editor-fold>
    }

    public void CreateMainGUI() {
        // <editor-fold defaultstate="collapsed" desc="Main INIT">  
        JTabbedPane tabs = new JTabbedPane();
        ImageIcon createEntryIcon = createImageIcon(newentryiconpath, 20, 20);
        ImageIcon editEntriesIcon = createImageIcon(editentriesiconpath, 20, 20);
        ImageIcon reportsIcon = createImageIcon(reportsiconpath, 20, 20);
        this.setSize(350, 500);

        tabs.addTab("New Entry", createEntryIcon, CreateNewEntryGUI(),
                "Add new transaction entry.");
        tabs.setMnemonicAt(0, KeyEvent.VK_1);

        tabs.addTab("Edit Entries", editEntriesIcon, CreateEditEntriesGUI(),
                "Edit a transaction entry of a specific date.");
        tabs.setMnemonicAt(1, KeyEvent.VK_2);

        tabs.addTab("Monthly Reports", reportsIcon, CreateReportsGUI(),
                "Create monthly Profit & Loss reports.");
        tabs.setMnemonicAt(2, KeyEvent.VK_3);

        tabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

        tabs.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent changeEvent) {
                int currentTab = ((JTabbedPane) changeEvent.getSource()).getSelectedIndex();

                final int ADD_ENTRY_TAB = 0;
                final int EDIT_ENTRIES_TAB = 1;
                final int CREATE_REPORTS_TAB = 2;

                switch (previousTab) {
                    case ADD_ENTRY_TAB:
                        if (currentTab == EDIT_ENTRIES_TAB
                                || currentTab == CREATE_REPORTS_TAB) {
                            if ((!ammountF.getText().isEmpty()
                                    && !ammountF.getText().equals("0.00")
                                    || !descriptionT.getText().isEmpty())) {
                                ((JTabbedPane) changeEvent.getSource()).setSelectedIndex(ADD_ENTRY_TAB);
                                int opt = JOptionPane.showOptionDialog(me,
                                        "You haven't saved the new transaction entry.\nAre you sure you want to leave this tab?",
                                        "Entry not saved",
                                        JOptionPane.YES_NO_OPTION,
                                        JOptionPane.QUESTION_MESSAGE, null, null, null
                                );
                                if (opt == JOptionPane.OK_OPTION) {
                                    ammountF.setText("");
                                    descriptionT.setText("");
                                    dateF.setText("");
                                    typeC.setSelectedIndex(0);
                                    if (currentTab == EDIT_ENTRIES_TAB) {
                                        setSize(350, 238);
                                        previousTab = EDIT_ENTRIES_TAB;
                                        ((JTabbedPane) changeEvent.getSource()).setSelectedIndex(EDIT_ENTRIES_TAB);
                                    }
                                    if (currentTab == CREATE_REPORTS_TAB) {
                                        setSize(350, 168);
                                        previousTab = CREATE_REPORTS_TAB;
                                        ((JTabbedPane) changeEvent.getSource()).setSelectedIndex(CREATE_REPORTS_TAB);
                                    }
                                }
                            } else {
                                ammountF.setText("");
                                descriptionT.setText("");
                                dateF.setText("");
                                typeC.setSelectedIndex(0);
                                if (currentTab == EDIT_ENTRIES_TAB) {
                                    setSize(350, 238);
                                    previousTab = EDIT_ENTRIES_TAB;
                                }
                                if (currentTab == CREATE_REPORTS_TAB) {
                                    setSize(350, 168);
                                    previousTab = CREATE_REPORTS_TAB;
                                }
                            }
                        }
                        break;
                    case EDIT_ENTRIES_TAB:
                        if (currentTab == ADD_ENTRY_TAB
                                || currentTab == CREATE_REPORTS_TAB) {
                            if (ammountChanged || descriptionChanged || dateChanged || typeChanged) {
                                ((JTabbedPane) changeEvent.getSource()).setSelectedIndex(EDIT_ENTRIES_TAB);
                                int opt = JOptionPane.showOptionDialog(me,
                                        "You haven't saved your changes.\nAre you sure you want to leave this tab?",
                                        "Changes not saved",
                                        JOptionPane.YES_NO_OPTION,
                                        JOptionPane.QUESTION_MESSAGE, null, null, null
                                );
                                if (opt == 0) {
                                    selectDateF.setText("");
                                    selectIDC.removeAllItems();
                                    selectIDC.addItem("...");
                                    selectIDC.setEnabled(false);
                                    ammount2F.setText("");
                                    description2T.setText("");
                                    date2F.setText("");
                                    type2C.setSelectedIndex(0);
                                    ammountChanged = false;
                                    descriptionChanged = false;
                                    dateChanged = false;
                                    typeChanged = false;
                                    ammountBackup = "";
                                    descriptionBackup = "";
                                    dateBackup = "";
                                    typeBackup = "";
                                    if (currentTab == ADD_ENTRY_TAB) {
                                        setSize(350, 500);
                                        previousTab = ADD_ENTRY_TAB;
                                        ((JTabbedPane) changeEvent.getSource()).setSelectedIndex(ADD_ENTRY_TAB);
                                    }
                                    if (currentTab == CREATE_REPORTS_TAB) {
                                        setSize(350, 168);
                                        previousTab = CREATE_REPORTS_TAB;
                                        ((JTabbedPane) changeEvent.getSource()).setSelectedIndex(CREATE_REPORTS_TAB);
                                    }
                                }
                            } else {
                                selectDateF.setText("");
                                selectIDC.removeAllItems();
                                selectIDC.addItem("...");
                                selectIDC.setEnabled(false);
                                ammount2F.setText("");
                                description2T.setText("");
                                date2F.setText("");
                                type2C.setSelectedIndex(0);
                                ammountChanged = false;
                                descriptionChanged = false;
                                dateChanged = false;
                                typeChanged = false;
                                ammountBackup = "";
                                descriptionBackup = "";
                                dateBackup = "";
                                typeBackup = "";
                                if (currentTab == ADD_ENTRY_TAB) {
                                    setSize(350, 500);
                                    previousTab = ADD_ENTRY_TAB;
                                }
                                if (currentTab == CREATE_REPORTS_TAB) {
                                    setSize(350, 168);
                                    previousTab = CREATE_REPORTS_TAB;
                                }
                            }
                        }
                        break;
                    case CREATE_REPORTS_TAB:
                        if (currentTab == EDIT_ENTRIES_TAB
                                || currentTab == ADD_ENTRY_TAB) {

                            if (currentTab == ADD_ENTRY_TAB) {
                                selectMonthF.setText("");
                                entriesPane.setText("");
                                sumF.setText("");
                                setSize(350, 500);
                                previousTab = ADD_ENTRY_TAB;
                            }
                            if (currentTab == EDIT_ENTRIES_TAB) {
                                selectMonthF.setText("");
                                entriesPane.setText("");
                                sumF.setText("");
                                setSize(350, 238);
                                previousTab = EDIT_ENTRIES_TAB;
                            }
                        }
                        break;
                    default:
                        switch (currentTab) {
                            case ADD_ENTRY_TAB:
                                setSize(350, 500);
                                previousTab = ADD_ENTRY_TAB;
                                break;
                            case EDIT_ENTRIES_TAB:
                                setSize(350, 238);
                                previousTab = EDIT_ENTRIES_TAB;
                                break;
                            case CREATE_REPORTS_TAB:
                                setSize(350, 168);
                                previousTab = CREATE_REPORTS_TAB;
                                break;
                            default:
                                throw new AssertionError();
                        }
                }
            }
        });

        tabs.setSelectedIndex(2);

        pane = new JPanel();
        pane.setLayout(new GridLayout(1, 1));
        this.setContentPane(pane);

        pane.add(tabs);
        // </editor-fold>
    }

    public JLabel CreateNewEntryGUI() {
        // <editor-fold defaultstate="collapsed" desc="New Entry Tab INIT">  

        int cmarginX = 50;
        int cmarginY = 0;
        int spaceY = 20;

        JLabel backL = new JLabel(
                createImageIcon(backgroundpath, 350, 435));
        backL.setLayout(null);

        JLabel titleL = new JLabel("Transaction Details");
        titleL.setBounds(cmarginX + 55, cmarginY, cwidth, cheight);

        cmarginY += spaceY + 8;

        JSeparator sep = new JSeparator(SwingConstants.HORIZONTAL);
        sep.setBounds(0, cmarginY, 350, 10);
        sep.setBackground(Color.white);

        cmarginY += spaceY / 2 + 2;

        JLabel ammountL = new JLabel("Ammount");
        ammountL.setBounds(cmarginX, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        ammountF = new JTextField("");
        ammountF.setBounds(cmarginX, cmarginY, cwidth + 20, cheight);
        ammountF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
        ammountF.setDocument(new AmmountDocument(22, ammountF));
        JTextField currF = new JTextField("EUR");
        currF.setBounds(cmarginX + cwidth + 20, cmarginY, 30, cheight);
        currF.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
        currF.setEditable(false);
        currF.setBackground(new Color(80, 80, 80));

        cmarginY += cheight + spaceY;

        JLabel descriptionL = new JLabel("Description");
        descriptionL.setBounds(cmarginX, cmarginY, cwidth, cheight);
        descriptionT = new JTextArea();
        descriptionT.setLineWrap(true);
        descriptionT.setWrapStyleWord(true);
        descriptionT.setDocument(new AmmountDocument(200));

        cmarginY += cheight;

        descriptionS = new JScrollPane(descriptionT, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        descriptionS.setBounds(cmarginX, cmarginY, cwidth + 50, cheight + 60);
        descriptionS.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

        cmarginY += cheight + 60 + spaceY;

        JLabel dateL = new JLabel("Date");
        dateL.setBounds(cmarginX, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        dateF = new JTextField();
        dateF.setEditable(false);
        dateF.setBackground(new Color(80, 80, 80));
        dateF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
        dateF.setBounds(cmarginX, cmarginY, cwidth + 30, cheight);

        calB = new JButton(createImageIcon(caliconpath, 17, 22));
        calB.setFocusPainted(false);
        calB.setBounds(cmarginX + 230, cmarginY, 18, cheight);
        calB.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
        calB.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dateF.setText(new DatePicker(me, dateFormat).getPickedDate());
            }
        });

        cmarginY += cheight + spaceY;

        JLabel typeL = new JLabel("Type");
        typeL.setBounds(cmarginX, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        typeC = new JComboBox<String>(new String[]{"...", "Profit", "Loss"});
        typeC.setBounds(cmarginX, cmarginY, cwidth + 50, cheight);
        typeC.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

        cmarginY += cheight + spaceY + 10;

        saveB = new JButton("Save");
        saveB.setFocusPainted(false);
        saveB.setBounds(cmarginX, cmarginY, 90, cheight);
        saveB.addActionListener(saveBNewEntryTabGUI);

        JButton cancelB = new JButton("Clear");
        cancelB.setFocusPainted(false);
        cancelB.setBounds(cmarginX + 160, cmarginY, 90, cheight);
        cancelB.addActionListener(cancelBNewEntryTabGUI);

        backL.add(titleL);
        backL.add(sep);
        backL.add(ammountL);
        backL.add(ammountF);
        backL.add(currF);
        backL.add(descriptionL);
        backL.add(descriptionS);
        backL.add(dateL);
        backL.add(dateF);
        backL.add(calB);
        backL.add(typeL);
        backL.add(typeC);
        backL.add(saveB);
        backL.add(cancelB);

        return backL;
        // </editor-fold>
    }

    public JLabel CreateEditEntriesGUI() {
        // <editor-fold defaultstate="collapsed" desc="Edit Entries Tab INIT">  

        int cmarginX = 50;
        int cmarginY = 0;
        int spaceY = 20;

        JLabel backL = new JLabel(
                createImageIcon(backgroundpath, 350, 700));
        backL.setLayout(null);

        JLabel titleL = new JLabel("Select Accounting Record");
        titleL.setBounds(cmarginX + 55, cmarginY, cwidth, cheight);

        cmarginY += spaceY + 8;

        JSeparator sep = new JSeparator(SwingConstants.HORIZONTAL);
        sep.setBounds(0, cmarginY, 350, 10);
        sep.setBackground(Color.white);

        cmarginY += spaceY / 2 + 2;

        JLabel selectDateL = new JLabel("Select record's date");
        selectDateL.setBounds(cmarginX, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        selectDateF = new JTextField();
        selectDateF.setEditable(false);
        selectDateF.setBackground(new Color(80, 80, 80));
        selectDateF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
        selectDateF.setBounds(cmarginX, cmarginY, cwidth + 30, cheight);

        JButton calB = new JButton(createImageIcon(caliconpath, 17, 22));
        calB.setFocusPainted(false);
        calB.setBounds(cmarginX + 230, cmarginY, 18, cheight);
        calB.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
        calB.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                boolean noDanger = true;
                approved = true;
                if (ammountChanged || descriptionChanged || dateChanged || typeChanged) {
                    noDanger = false;
                    approved = false;
                    int opt = JOptionPane.showOptionDialog(me,
                            "You are going to loose your changes!\nAre you sure?",
                            "Confirm to discard",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.QUESTION_MESSAGE, null, null, null
                    );
                    if (opt == 0) {
                        noDanger = true;
                        ammountChanged = false;
                        descriptionChanged = false;
                        dateChanged = false;
                        typeChanged = false;
                        ammountBackup = "";
                        descriptionBackup = "";
                        dateBackup = "";
                        typeBackup = "";
                        approved = true;
                    }
                }
                if (noDanger) {
                    selectIDC.removeAllItems();
                    selectIDC.addItem("...");
                    selectDateF.setText(new DatePicker(me, dateFormat).getPickedDate());
                    selectIDC.setEnabled(true);
                    ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                    description2S.setBorder(BorderFactory.createLineBorder(Color.gray, 1));
                    date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                    cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.gray));
                    updateSelectIDC();
                    ammountChanged = false;
                    descriptionChanged = false;
                    dateChanged = false;
                    typeChanged = false;
                    ammountBackup = "";
                    descriptionBackup = "";
                    dateBackup = "";
                    typeBackup = "";
                }
            }
        });

        cmarginY += cheight + spaceY;

        JLabel selectIDL = new JLabel("Select record's id");
        selectIDL.setBounds(cmarginX, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        selectIDC = new JComboBox<String>(new String[]{"..."});
        selectIDC.setBounds(cmarginX, cmarginY, cwidth + 50, cheight);
        selectIDC.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));
        selectIDC.setEnabled(false);
        selectIDC.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent itemEvent) {
                if (itemEvent.getStateChange() == ItemEvent.SELECTED) {
                    if (((String) itemEvent.getItem()).equals("...")) {
                        setSize(350, 238);
                    } else {
                        setSize(350, 680);
                        boolean noDanger = true;
                        if ((ammountChanged || descriptionChanged || dateChanged || typeChanged)
                                && selectIDC.getSelectedIndex() != idCindexBackup) {
                            noDanger = false;
                            int opt = JOptionPane.showOptionDialog(me,
                                    "You are going to loose your changes!\nAre you sure?",
                                    "Confirm to discard",
                                    JOptionPane.YES_NO_OPTION,
                                    JOptionPane.QUESTION_MESSAGE, null, null, null
                            );
                            approved = false;
                            if (opt == 0) {
                                noDanger = true;
                                ammountChanged = false;
                                descriptionChanged = false;
                                dateChanged = false;
                                typeChanged = false;
                                ammountBackup = "";
                                descriptionBackup = "";
                                dateBackup = "";
                                typeBackup = "";
                                approved = true;
                            } else {
                                selectIDC.setSelectedIndex(idCindexBackup);
                            }
                        }
                        if (noDanger && approved) {
                            ammountChanged = false;
                            descriptionChanged = false;
                            dateChanged = false;
                            typeChanged = false;
                            ammountBackup = "";
                            descriptionBackup = "";
                            dateBackup = "";
                            typeBackup = "";
                            idCindexBackup = selectIDC.getSelectedIndex();
                            TransactionEntry selectedEntry = Main.getEntryByID(
                                    ((String) itemEvent.getItem()).replace("#", ""));

                            ammount2F.setText(selectedEntry.getAmmount());
                            ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                            ammountBackup = ammount2F.getText();
                            ammount2F.getDocument().addDocumentListener(new DocumentListener() {

                                @Override
                                public void insertUpdate(DocumentEvent e) {
                                    if (!ammountBackup.isEmpty()) {
                                        if (!ammount2F.getText().equals(ammountBackup)) {
                                            ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.yellow));
                                            ammountChanged = true;
                                        } else {
                                            ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                                            ammountChanged = false;
                                        }
                                    }
                                }

                                @Override
                                public void removeUpdate(DocumentEvent e) {
                                    if (!ammountBackup.isEmpty()) {
                                        if (!ammount2F.getText().equals(ammountBackup)) {
                                            ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.yellow));
                                            ammountChanged = true;
                                        } else {
                                            ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                                            ammountChanged = false;
                                        }
                                    }
                                }

                                @Override
                                public void changedUpdate(DocumentEvent e) {
                                    if (!ammountBackup.isEmpty()) {
                                        if (!ammount2F.getText().equals(ammountBackup)) {
                                            ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.yellow));
                                            ammountChanged = true;
                                        } else {
                                            ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                                            ammountChanged = false;
                                        }
                                    }
                                }

                            });
                            description2T.setText(selectedEntry.getDescription());
                            description2S.setBorder(BorderFactory.createLineBorder(Color.gray, 1));
                            descriptionBackup = description2T.getText();
                            description2T.getDocument().addDocumentListener(new DocumentListener() {

                                @Override
                                public void insertUpdate(DocumentEvent e) {
                                    if (!descriptionBackup.isEmpty()) {
                                        if (!description2T.getText().equals(descriptionBackup)) {
                                            description2S.setBorder(BorderFactory.createLineBorder(Color.yellow, 1));
                                            descriptionChanged = true;
                                        } else {
                                            description2S.setBorder(BorderFactory.createLineBorder(Color.gray, 1));
                                            descriptionChanged = false;
                                        }
                                    }
                                }

                                @Override
                                public void removeUpdate(DocumentEvent e) {
                                    if (!descriptionBackup.isEmpty()) {
                                        if (!description2T.getText().equals(descriptionBackup)) {
                                            description2S.setBorder(BorderFactory.createLineBorder(Color.yellow, 1));
                                            descriptionChanged = true;
                                        } else {
                                            description2S.setBorder(BorderFactory.createLineBorder(Color.gray, 1));
                                            descriptionChanged = false;
                                        }
                                    }
                                }

                                @Override
                                public void changedUpdate(DocumentEvent e) {
                                    if (!descriptionBackup.isEmpty()) {
                                        if (!description2T.getText().equals(descriptionBackup)) {
                                            description2S.setBorder(BorderFactory.createLineBorder(Color.yellow, 1));
                                            descriptionChanged = true;
                                        } else {
                                            description2S.setBorder(BorderFactory.createLineBorder(Color.gray, 1));
                                            descriptionChanged = false;
                                        }
                                    }
                                }

                            });
                            date2F.setText(selectedEntry.getDate());
                            date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                            cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.gray));
                            dateBackup = date2F.getText();
                            date2F.getDocument().addDocumentListener(new DocumentListener() {

                                @Override
                                public void insertUpdate(DocumentEvent e) {
                                    if (!dateBackup.isEmpty()) {
                                        if (!date2F.getText().equals(dateBackup)) {
                                            date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.yellow));
                                            cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.yellow));
                                            dateChanged = true;
                                        } else {
                                            date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                                            cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.gray));
                                            dateChanged = false;
                                        }
                                    }
                                }

                                @Override
                                public void removeUpdate(DocumentEvent e) {
                                    if (!dateBackup.isEmpty()) {
                                        if (!date2F.getText().equals(dateBackup)) {
                                            date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.yellow));
                                            cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.yellow));
                                            dateChanged = true;
                                        } else {
                                            date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                                            cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.gray));
                                            dateChanged = false;
                                        }
                                    }
                                }

                                @Override
                                public void changedUpdate(DocumentEvent e) {
                                    if (!dateBackup.isEmpty()) {
                                        if (!date2F.getText().equals(dateBackup)) {
                                            date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.yellow));
                                            cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.yellow));
                                            dateChanged = true;
                                        } else {
                                            date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.gray));
                                            cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.gray));
                                            dateChanged = false;
                                        }
                                    }
                                }

                            });
                            type2C.setSelectedIndex(selectedEntry.getType());
                            type2C.setBorder(BorderFactory.createLineBorder(Color.gray, 1));
                            typeBackup = (String) type2C.getSelectedItem();
                            type2C.addItemListener(new ItemListener() {

                                @Override
                                public void itemStateChanged(ItemEvent e) {
                                    if (!typeBackup.isEmpty()) {
                                        if (!((String) e.getItem()).equals(typeBackup)) {
                                            type2C.setBorder(BorderFactory.createLineBorder(Color.yellow, 1));
                                            typeChanged = true;
                                        } else {
                                            type2C.setBorder(BorderFactory.createLineBorder(Color.gray, 1));
                                            typeChanged = false;
                                        }
                                    }
                                }

                            });
                        }
                    }
                }
            }
        });

        cmarginY += cheight + spaceY / 2 + 2;

        JSeparator sep2 = new JSeparator(SwingConstants.HORIZONTAL);
        sep2.setBounds(0, cmarginY, 350, 10);
        sep2.setBackground(Color.white);

        cmarginY += spaceY / 2 - 2;

        JLabel title2L = new JLabel("Transaction Details");
        title2L.setBounds(cmarginX + 55, cmarginY, cwidth, cheight);

        cmarginY += spaceY + 8;

        JSeparator sep3 = new JSeparator(SwingConstants.HORIZONTAL);
        sep3.setBounds(0, cmarginY, 350, 10);
        sep3.setBackground(Color.white);

        cmarginY += spaceY / 2 + 2;

        JLabel ammountL = new JLabel("Ammount");
        ammountL.setBounds(cmarginX, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        ammount2F = new JTextField("0.00");
        ammount2F.setBounds(cmarginX, cmarginY, cwidth + 20, cheight);
        ammount2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
        ammount2F.setDocument(new AmmountDocument(22, ammount2F));
        JTextField curr2F = new JTextField("EUR");
        curr2F.setBounds(cmarginX + cwidth + 20, cmarginY, 30, cheight);
        curr2F.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
        curr2F.setEditable(false);
        curr2F.setBackground(new Color(80, 80, 80));

        cmarginY += cheight + spaceY;

        JLabel descriptionL = new JLabel("Description");
        descriptionL.setBounds(cmarginX, cmarginY, cwidth, cheight);
        description2T = new JTextArea();
        description2T.setLineWrap(true);
        description2T.setWrapStyleWord(true);
        description2T.setDocument(new AmmountDocument(200));

        cmarginY += cheight;

        description2S = new JScrollPane(description2T, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        description2S.setBounds(cmarginX, cmarginY, cwidth + 50, cheight + 60);
        description2S.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

        cmarginY += cheight + 60 + spaceY;

        JLabel dateL = new JLabel("Date");
        dateL.setBounds(cmarginX, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        date2F = new JTextField();
        date2F.setEditable(false);
        date2F.setBackground(new Color(80, 80, 80));
        date2F.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
        date2F.setBounds(cmarginX, cmarginY, cwidth + 30, cheight);

        cal2B = new JButton(createImageIcon(caliconpath, 17, 22));
        cal2B.setFocusPainted(false);
        cal2B.setBounds(cmarginX + 230, cmarginY, 18, cheight);
        cal2B.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
        cal2B.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                date2F.setText(new DatePicker(me, dateFormat).getPickedDate());
            }
        });

        cmarginY += cheight + spaceY;

        JLabel typeL = new JLabel("Type");
        typeL.setBounds(cmarginX, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        type2C = new JComboBox<String>(new String[]{"...", "Profit", "Loss"});
        type2C.setBounds(cmarginX, cmarginY, cwidth + 50, cheight);
        type2C.setBorder(BorderFactory.createLineBorder(Color.GRAY, 1));

        cmarginY += cheight + spaceY + 10;

        save2B = new JButton("Save");
        save2B.setFocusPainted(false);
        save2B.setBounds(cmarginX, cmarginY, 90, cheight);
        save2B.addActionListener(saveBEditEntriesTabGUI);

        JButton restoreB = new JButton("Restore");
        restoreB.setFocusPainted(false);
        restoreB.setBounds(cmarginX + 160, cmarginY, 90, cheight);
        restoreB.addActionListener(restoreBEditEntriesTabGUI);

        backL.add(titleL);
        backL.add(sep);
        backL.add(selectDateL);
        backL.add(selectDateF);
        backL.add(calB);
        backL.add(selectIDL);
        backL.add(selectIDC);
        backL.add(sep2);
        backL.add(title2L);
        backL.add(sep3);
        backL.add(ammountL);
        backL.add(ammount2F);
        backL.add(curr2F);
        backL.add(descriptionL);
        backL.add(description2S);
        backL.add(dateL);
        backL.add(date2F);
        backL.add(cal2B);
        backL.add(typeL);
        backL.add(type2C);
        backL.add(save2B);
        backL.add(restoreB);

        return backL;
        // </editor-fold>
    }

    public JLabel CreateReportsGUI() {
        // <editor-fold defaultstate="collapsed" desc="Create Reports Tab INIT">  

        int cmarginX = 50;
        int cmarginY = 0;
        int spaceY = 20;

        JLabel backL = new JLabel(
                createImageIcon(backgroundpath, 350, 700));
        backL.setLayout(null);

        JLabel titleL = new JLabel("Create Monlty Financial Report");
        titleL.setBounds(cmarginX + 55, cmarginY, cwidth, cheight);

        cmarginY += spaceY + 8;

        JSeparator sep = new JSeparator(SwingConstants.HORIZONTAL);
        sep.setBounds(0, cmarginY, 350, 10);
        sep.setBackground(Color.white);

        cmarginY += spaceY / 2 + 2;

        JLabel selectMonthL = new JLabel("Select month and year");
        selectMonthL.setBounds(cmarginX, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        selectMonthF = new JTextField();
        selectMonthF.setEditable(false);
        selectMonthF.setBackground(new Color(80, 80, 80));
        selectMonthF.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 0, Color.GRAY));
        selectMonthF.setBounds(cmarginX, cmarginY, cwidth + 30, cheight);
        selectMonthF.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                if (!selectMonthF.getText().isEmpty()) {
                    entriesPane.setText("");
                    sumF.setText("");
                    setSize(350, 550);
                    double sum = 0;
                    try {
                        String monthYear = new java.text.SimpleDateFormat("MMMMM yyyy").format(
                                new java.text.SimpleDateFormat(monthYearFormat).parse(selectMonthF.getText()));

                        SimpleAttributeSet set = new SimpleAttributeSet();
                        StyleConstants.setForeground(set, Color.yellow);
                        entriesPane.getStyledDocument().insertString(entriesPane.getStyledDocument().getLength(),
                                "- " + monthYear + " -\n\n", set);
                        StyleConstants.setForeground(set, Color.white);
                        NumberFormat dform = new DecimalFormat("#,###,###,###,###.##"); 
                        for (TransactionEntry entry : Main.getEntriesWithSelectedMonth(selectMonthF.getText())) {
                            try {
                                entriesPane.getStyledDocument().insertString(entriesPane.getStyledDocument().getLength(),
                                        "Transcaction: #" + entry.getId()
                                        + ".\nType: " + (entry.getType() == TransactionEntry.INCOME ? "Income" : "Outcome")
                                        + ".\nDate: " + entry.getDate()
                                        + ".\nAmmount: ", set);
                                StyleConstants.setForeground(set, entry.getType() == TransactionEntry.INCOME ? Color.green : Color.red);
                                entriesPane.getStyledDocument().insertString(entriesPane.getStyledDocument().getLength(),
                                        entry.getAmmount(), set);
                                StyleConstants.setForeground(set, Color.white);
                                entriesPane.getStyledDocument().insertString(entriesPane.getStyledDocument().getLength(),
                                        ".\nDescription: " + entry.getDescription() + ".\n\n", set);
                            } catch (BadLocationException ex) {
                                ex.printStackTrace();
                            }
                            if (entry.getType() == TransactionEntry.INCOME) {
                                sum += Double.parseDouble(entry.getAmmount().replaceAll(",", ""));
                            } else {
                                sum -= Double.parseDouble(entry.getAmmount().replaceAll(",", ""));
                            }
                        }
                        sumF.setText(dform.format(sum));
                        if(sum<0){
                            sumF.setForeground(Color.red);
                        }else{
                            sumF.setForeground(Color.green);
                        }
                    } catch (ParseException ex) {
                        ex.printStackTrace();
                    } catch (BadLocationException ex) {
                        ex.printStackTrace();
                    }
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                if (!selectMonthF.getText().isEmpty()) {
                    setSize(350, 550);
                }
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                if (!selectMonthF.getText().isEmpty()) {
                    setSize(350, 550);
                }
            }
        });

        JButton calB = new JButton(createImageIcon(caliconpath, 17, 22));
        calB.setFocusPainted(false);
        calB.setBounds(cmarginX + 230, cmarginY, 18, cheight);
        calB.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
        calB.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectMonthF.setText("");
                entriesPane.setText("");
                sumF.setText("");
                setSize(350, 168);
                selectMonthF.setText(new MonthPicker(me, monthYearFormat, Main.getMonthsWithEntries()).getPickedMonth());
            }
        });

        cmarginY += cheight + spaceY / 2 + 2;

        JSeparator sep2 = new JSeparator(SwingConstants.HORIZONTAL);
        sep2.setBounds(0, cmarginY, 350, 10);
        sep2.setBackground(Color.white);

        cmarginY += spaceY / 2 - 2;

        JLabel title2L = new JLabel("Financial Report");
        title2L.setBounds(cmarginX + 55, cmarginY, cwidth, cheight);

        cmarginY += spaceY + 8;

        JSeparator sep3 = new JSeparator(SwingConstants.HORIZONTAL);
        sep3.setBounds(0, cmarginY, 350, 10);
        sep3.setBackground(Color.white);

        cmarginY += spaceY / 2 + 2;

        JLabel entriesL = new JLabel("Transaction Entries");
        entriesL.setBounds(cmarginX - 30, cmarginY, cwidth, cheight);

        cmarginY += cheight;

        entriesPane = new JTextPane();
        entriesPane.setEditable(false);
        JScrollPane entriesS = new JScrollPane(entriesPane, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        entriesS.setBounds(cmarginX - 30, cmarginY, cwidth + 100, cheight + 200);
        entriesS.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));

        cmarginY += cheight + spaceY + 200;

        JLabel sumL = new JLabel("Summary:");
        sumL.setBounds(cmarginX - 5, cmarginY, cwidth+50, cheight);

        cmarginY += cheight;

        sumF = new JTextField();
        sumF.setBounds(cmarginX -5, cmarginY, cwidth+20, cheight);
        sumF.setBackground(new Color(80, 80, 80));
        sumF.setEditable(false);
        sumF.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
        JTextField currF = new JTextField("EUR");
        currF.setBounds(cmarginX -5 + cwidth + 20, cmarginY, 30, cheight);
        currF.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, Color.GRAY));
        currF.setEditable(false);
        currF.setBackground(new Color(80, 80, 80));

        backL.add(titleL);
        backL.add(sep);
        backL.add(selectMonthL);
        backL.add(selectMonthF);
        backL.add(calB);
        backL.add(sep2);
        backL.add(title2L);
        backL.add(sep3);
        backL.add(entriesL);
        backL.add(entriesS);
        backL.add(sumL);
        backL.add(sumF);
        backL.add(currF);

        return backL;
        // </editor-fold>
    }

    public void updateSelectIDC() {
        String selectedDate = selectDateF.getText();

        ArrayList<TransactionEntry> entries = Main.getEntriesWithSelectedDate(selectedDate);

        for (TransactionEntry entry : entries) {
            selectIDC.addItem("#" + entry.getId());
        }
    }

    public void getCustomFont(String path) {
        try {
            GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
            ge.registerFont(Font.createFont(Font.TRUETYPE_FONT, new File(path)));
        } catch (FontFormatException | IOException e) {
            e.printStackTrace();
        }
    }

    public void setIcon(String path) {
        ImageIcon img = new ImageIcon(path);
        this.setIconImage(img.getImage());
    }

    public ImageIcon createImageIcon(String path, int width, int height) {
        BufferedImage image;
        try {
            image = ImageIO.read(new File(path));
            return new ImageIcon(resize(image, width, height));
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public BufferedImage resize(BufferedImage img, int newW, int newH) {
        Image tmp = img.getScaledInstance(newW, newH, Image.SCALE_SMOOTH);
        BufferedImage dimg = new BufferedImage(newW, newH, BufferedImage.TYPE_INT_ARGB);

        Graphics2D g2d = dimg.createGraphics();
        g2d.drawImage(tmp, 0, 0, null);
        g2d.dispose();

        return dimg;

    }
}

class DatePicker {

    // <editor-fold defaultstate="collapsed" desc="Date Picker">  
    //https://eureka.ykyuen.info/2011/09/05/java-swing-datepicker-1/
    private int month = java.util.Calendar.getInstance().get(java.util.Calendar.MONTH);
    private int year = java.util.Calendar.getInstance().get(java.util.Calendar.YEAR);
    private JLabel l = new JLabel("", JLabel.CENTER);
    private String day = "";
    private JDialog dialog;
    private JButton[] button = new JButton[49];
    private java.text.SimpleDateFormat sdf;

    public DatePicker(JFrame parent, String dateFormat) {

        sdf = new java.text.SimpleDateFormat(dateFormat);

        dialog = new JDialog();
        dialog.setModal(true);
        dialog.setUndecorated(true);

        String[] header = {"Sun", "Mon", "Tue", "Wed", "Thur", "Fri", "Sat"};
        JPanel p1 = new JPanel(new GridLayout(7, 7));
        p1.setPreferredSize(new Dimension(430, 120));
        JLabel monthL = new JLabel(new java.text.SimpleDateFormat("MMMMM")
                .format(java.util.Calendar.getInstance().getTime()));
        monthL.setHorizontalAlignment(JLabel.CENTER);
        monthL.setBackground(Color.gray);
        for (int x = 0; x < button.length; x++) {

            final int selection = x;

            button[x] = new JButton();
            button[x].setFocusPainted(false);
            button[x].setBackground(Color.gray.darker().darker().darker());

            if (x < 7) {
                button[x].setText(header[x]);
                button[x].setForeground(Color.white);
            }
            p1.add(button[x]);
        }
        JPanel p2 = new JPanel(new GridLayout(1, 3));

        JButton previous = new JButton("<<");
        previous.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ae) {
                month--;
                displayDate();
                java.util.Calendar cal = java.util.Calendar.getInstance();
                cal.set(year, month, 1);
                monthL.setText(new java.text.SimpleDateFormat("MMMMM").format(cal.getTime()));
            }
        });
        p2.add(previous);
        p2.add(l);

        JButton next = new JButton(">>");

        next.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ae) {
                if (month < java.util.Calendar.getInstance().get(java.util.Calendar.MONTH)) {
                    month++;
                    displayDate();
                    java.util.Calendar cal = java.util.Calendar.getInstance();
                    cal.set(year, month, 1);
                    monthL.setText(new java.text.SimpleDateFormat("MMMMM").format(cal.getTime()));
                }
            }
        });
        p2.add(next);
        dialog.add(monthL, BorderLayout.NORTH);
        dialog.add(p1, BorderLayout.CENTER);
        dialog.add(p2, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setLocationRelativeTo(parent);
        displayDate();
        dialog.setVisible(true);
    }

    public void displayDate() {
        for (int x = 7; x < button.length; x++) {
            button[x].setText("");
        }
        java.util.Calendar cal = java.util.Calendar.getInstance();
        cal.set(year, month, 1);
        int dayOfWeek = cal.get(java.util.Calendar.DAY_OF_WEEK);
        int daysInMonth = cal.getActualMaximum(java.util.Calendar.DAY_OF_MONTH);

        for (int x = 6 + dayOfWeek, d = 1; d <= daysInMonth; x++, d++) {
            final int selection = x;
            if (month <= java.util.Calendar.getInstance().get(java.util.Calendar.MONTH)
                    && year <= java.util.Calendar.getInstance().get(java.util.Calendar.YEAR)) {
                if (month == java.util.Calendar.getInstance().get(java.util.Calendar.MONTH)
                        && year == java.util.Calendar.getInstance().get(java.util.Calendar.YEAR)) {
                    if (d <= java.util.Calendar.getInstance().get(java.util.Calendar.DAY_OF_MONTH)) {
                        button[x].setText("" + d);
                        button[x].addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent ae) {
                                day = button[selection].getActionCommand();
                                dialog.dispose();
                            }
                        });
                    }
                } else {
                    button[x].setText("" + d);
                    button[x].addActionListener(new ActionListener() {
                        public void actionPerformed(ActionEvent ae) {
                            day = button[selection].getActionCommand();
                            dialog.dispose();
                        }
                    });
                }
            }
        }
        l.setText(sdf.format(cal.getTime()));
        dialog.setTitle("Pick date");
    }

    public String getPickedDate() {
        if (day.isEmpty()) {
            return "";
        } else {

            java.util.Calendar cal = java.util.Calendar.getInstance();
            try {
                cal.set(year, month, Integer.parseInt(day));
            } catch (NumberFormatException e) {

            }

            return sdf.format(cal.getTime());
        }
    }
    //</editor-fold>
}

class AmmountDocument extends PlainDocument {

    // <editor-fold defaultstate="collapsed" desc="Ammount Document">  
    private int limit;
    private boolean ammountField;
    private JTextComponent comp;

    AmmountDocument(int limit) {
        super();
        this.limit = limit;
    }

    AmmountDocument(int limit, JTextComponent comp) {
        super();
        this.limit = limit;
        this.ammountField = true;
        this.comp = comp;
    }

    @Override
    public void insertString(int offset, String str, AttributeSet attr) throws BadLocationException {
        if (str == null) {
            return;
        }
        if ((getLength() + str.length()) <= limit) {
            if (ammountField) {
                if (str.equals(".")) {
                    if (!getText(0, getLength()).contains(".") && offset != 0) {
                        super.insertString(offset, str, attr);
                    } else {
                        comp.setCaretPosition(getText(0, getLength()).indexOf(".") + 1);
                    }
                } else {
                    String prevString = getText(0, getLength());
                    String currStr = prevString.substring(0, offset) + str + prevString.substring(offset, prevString.length());
                    try {
                        double d = Double.parseDouble(currStr.replaceAll(",", ""));
                        String finalStr = new DecimalFormat("###,###,###,###.##").format(d);

                        int posfix = 0;
                        if (!finalStr.contains(".")) {
                            finalStr += ".00";
                            if (offset == 0) {
                                posfix -= 3;
                            }
                        } else {
                            if (finalStr.length() == finalStr.indexOf(".") + 2) {
                                finalStr += "0";
                                posfix += 1;
                            }
                        }
                        posfix += finalStr.length() - currStr.length();
                        posfix = offset + posfix + 1;
                        posfix = posfix > finalStr.length() ? finalStr.length() : posfix;
                        if (!finalStr.contains(".")) {
                            finalStr += ".00";
                        }
                        super.remove(0, getLength());
                        super.insertString(0, finalStr, attr);
                        comp.setCaretPosition(posfix);
                    } catch (Exception ex) {
                    }
                }
            } else {
                super.insertString(offset, str, attr);
            }
        }
    }
    // </editor-fold>
}

class MonthPicker {

    private JDialog dialog;
    private JButton[] buttons = new JButton[12];
    private String[] monthsStr = {"January", "February", "March", "April", "May", "June", "Jule", "August", "September", "October", "November", "December"};
    private JPanel monthsP;

    private ArrayList<ArrayList<Integer>> months;

    private int selectedMonth = -1;
    private int selectedYear = -1;
    ;
    private int currentYear;
    private int maxYear;

    private String format;

    public MonthPicker(JFrame parent, String format, ArrayList<ArrayList<Integer>> months) {

        if (months.isEmpty()) {
            throw new NullPointerException();
        }
        dialog = new JDialog();
        dialog.setModal(true);
        dialog.setUndecorated(true);

        maxYear = months.get(0).get(1);
        for (ArrayList<Integer> my : months) {
            int y = my.get(1);
            if (y > maxYear) {
                maxYear = y;
            }
        }

        this.format = format;
        this.months = months;

        monthsP = new JPanel(new GridLayout(4, 3));
        monthsP.setPreferredSize(new Dimension(500, 100));

        currentYear = Integer.parseInt(new java.text.SimpleDateFormat("yyyy")
                .format(java.util.Calendar.getInstance().getTime()));

        updateMonthsP();

        JPanel p2 = new JPanel(new GridLayout(1, 3));

        JLabel yearL = new JLabel("" + currentYear);
        yearL.setHorizontalAlignment(JLabel.CENTER);
        yearL.setBackground(Color.gray);

        JButton previous = new JButton("<<");
        previous.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ae) {
                currentYear--;
                yearL.setText("" + currentYear);
                updateMonthsP();
            }
        });
        p2.add(previous);
        p2.add(yearL);

        JButton next = new JButton(">>");

        next.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent ae) {
                if (maxYear > currentYear) {
                    currentYear++;
                    yearL.setText("" + currentYear);
                    updateMonthsP();
                }
            }
        });

        p2.add(next);
        dialog.add(monthsP, BorderLayout.CENTER);
        dialog.add(p2, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setLocationRelativeTo(parent);
        dialog.setTitle("Pick month");
        dialog.setVisible(true);
    }

    public void updateMonthsP() {
        monthsP.removeAll();
        for (int x = 0; x < buttons.length; x++) {
            if (months.contains(new ArrayList<Integer>(Arrays.asList(x, currentYear)))) {
                buttons[x] = new JButton();
                buttons[x].setFocusPainted(false);
                buttons[x].setBackground(Color.gray.darker().darker().darker());
                buttons[x].setText(monthsStr[x]);
                buttons[x].setName(x + "");
                buttons[x].addActionListener(new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        selectedMonth = Integer.parseInt(((JButton) e.getSource()).getName());
                        selectedYear = currentYear;
                        dialog.dispose();
                    }

                });
                monthsP.add(buttons[x]);
            } else {
                monthsP.add(new JLabel(""));
            }
        }
    }

    public String getPickedMonth() {

        if (selectedYear == -1 || selectedMonth == -1) {
            return "";
        } else {
            java.util.Calendar cal = java.util.Calendar.getInstance();

            cal.set(currentYear, selectedMonth, 1);
            return new java.text.SimpleDateFormat(format).format(cal.getTime());
        }
    }
}
