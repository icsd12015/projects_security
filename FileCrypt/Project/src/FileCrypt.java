/**  321/2012015 - Aylakiotis Christos
 *   icsd11063   - Katsivelis Kwn/nos
 */
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileSystemView;


public class FileCrypt{
    private Digest digest;
    private SecretKey sKey;
    private final HashMap<String,Boolean> isEncrypted = new HashMap(); //Voithaei sto na vriskei poia arxeia einai kwdikopoihmena
                                                                        //(gia ti leitourgia tou koumpiou (encrypt/decrypt)
    
    public void showLoginGUI(){
        JFrame frame = new JFrame("Files Vault Login");
        
        JLabel loginL = new JLabel("Σύνδεση Χρήστη:");
        loginL.setBounds(200, 50, 200, 20);
        loginL.setFont(new Font("Tahoma", Font.BOLD, 19));
        loginL.setForeground(Color.white);
        
        JLabel usernameL = new JLabel("'Ονομα Χρήστη");
        usernameL.setBounds(250, 80, 200, 20);
        usernameL.setFont(new Font("Tahoma", Font.PLAIN, 15));
        usernameL.setForeground(Color.blue);
        
        JTextField usernameF = new JTextField();
        usernameF.setBounds(250, 100, 200, 20);
        usernameF.setBackground(Color.black);
        
        JLabel passwordL = new JLabel("Κωδικός Χρήστη");
        passwordL.setBounds(250, 120, 200, 20);
        passwordL.setFont(new Font("Tahoma", Font.PLAIN, 15));
        passwordL.setForeground(Color.blue);
        
        JPasswordField passwordF = new JPasswordField();
        passwordF.setBounds(250, 140, 200, 20);
        passwordF.setBackground(Color.black);
        
        JLabel msgL = new JLabel("error message");
        msgL.setBounds(250, 200, 200, 20);
        msgL.setForeground(Color.red);
        msgL.setFont(new Font("Tahoma", Font.ITALIC, 13));
        msgL.setVisible(false);
        
        JButton loginB =new JButton("Σύνδεση");
        loginB.setBounds(370, 170, 120, 20);
        loginB.setForeground(Color.white);
        loginB.setBackground(Color.black);
        
        JLabel msg2L = new JLabel("error message");
        msg2L.setBounds(250, 420, 2050, 20);
        msg2L.setForeground(Color.red);
        msg2L.setFont(new Font("Tahoma", Font.ITALIC, 13));
        msg2L.setVisible(false);
        //Edw ginetai i authentikopoihsh tou xristi
        loginB.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                msg2L.setVisible(false);
                try{
                    msgL.setVisible(false);
                    
                    String username = usernameF.getText();
                    String password = passwordF.getText();
                    
                    if(username.isEmpty() || password.isEmpty()){
                        throw new Exception("Ύπάρχουν κενά πεδία.");
                    }
                    if(!loadUsersDigest(username)){
                        throw new Exception("'Ο χρήστης δεν υπάρχει.");
                    }
                    
                    PBKDF2 PBKDF2 = new PBKDF2(password, username, 2000, 32);
                    SecretKey sKey = PBKDF2.getDK(); //To sKey gia ti paragwgi tou authHash
                    SecretKey sKey256 = PBKDF2.getDK256(); //To sKey gia ti kwdikopoihsh AES256 twn arxeiwn
                    
                    //Paragwgi tou authHash
                    byte[] authHash = new PBKDF2(toHex(sKey.getEncoded()), password, 1000, 32).getDK().getEncoded();
                    
                    RSA2048 RSA2048 = new RSA2048();
                    //Apodikopoihsh tou zeugous <username,authHash> apo RSA2048
                    String digestDecrypted = RSA2048.decrypt(fromHex(digest.toString()));
                    
                    //pernw to username kai ti katopsi tou authHash apo to String
                    String digestParts[] = digestDecrypted.split("<|\\,|\\>"); 
                    
                    //Sugkrinw tis katopseis me tin methodo slowEquals wste to sustima na einai pio duskolo na spasei
                    if(slowEquals(fromHex(digestParts[2]),authHash)){
                        setSKey(sKey256);
                        showOptionsGUI(username);
                        frame.dispose();
                    }else{
                        throw new Exception("Λάθος κωδικός πρόσβασης.");
                    }
                    
                    
                }catch(Exception ex){
                    passwordF.setText("");
                    msgL.setText(ex.getMessage());
                    msgL.setVisible(true);
                }
            }
        });
        
        JLabel registerL = new JLabel("Νέος Χρήστης:");
        registerL.setBounds(200, 230, 200, 20);
        registerL.setFont(new Font("Tahoma", Font.BOLD, 19));
        registerL.setForeground(Color.white);
        
        JLabel nusernameL = new JLabel("'Ονομα Χρήστη");
        nusernameL.setBounds(250, 260, 200, 20);
        nusernameL.setFont(new Font("Tahoma", Font.PLAIN, 15));
        nusernameL.setForeground(Color.blue);
        
        JTextField nusernameF = new JTextField();
        nusernameF.setBounds(250, 280, 200, 20);
        nusernameF.setBackground(Color.black);
        
        JLabel npasswordL = new JLabel("Κωδικός Χρήστη");
        npasswordL.setBounds(250, 300, 200, 20);
        npasswordL.setFont(new Font("Tahoma", Font.PLAIN, 15));
        npasswordL.setForeground(Color.blue);
        
        JPasswordField npasswordF = new JPasswordField();
        npasswordF.setBounds(250, 320, 200, 20);
        npasswordF.setBackground(Color.black);
        
        JLabel npassword2L = new JLabel("Επαλήθευση Κωδικού");
        npassword2L.setBounds(250, 340, 200, 20);
        npassword2L.setFont(new Font("Tahoma", Font.PLAIN, 15));
        npassword2L.setForeground(Color.blue);
        
        JPasswordField npassword2F = new JPasswordField();
        npassword2F.setBounds(250, 360, 200, 20);
        npassword2F.setBackground(Color.black);
        
        JButton registerB =new JButton("Εγγραφή");
        registerB.setBounds(370, 390, 120, 20);
        registerB.setForeground(Color.white);
        registerB.setBackground(Color.black);
        
        //Edw ginetai i eggrafi neou xristi
        registerB.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e){
                msgL.setVisible(false);
                try{
                    String username = nusernameF.getText();
                    String password = npasswordF.getText();
                    
                    if(username.isEmpty() || password.isEmpty()
                            || npassword2F.getText().isEmpty()){
                        throw new Exception("Ύπάρχουν κενά πεδία.");
                    }
                    if(!npassword2F.getText().equals(password)){
                        throw new Exception("Οι κωδικοί δέν ταιριάζουν.");
                    }
                    if(loadUsersDigest(username)){
                        throw new Exception("Το όνομα χρήστη υπάρχει.");
                    }
                    msg2L.setVisible(false);
                    
                    //Paragwgi tou sKey 
                    SecretKey sKey = new PBKDF2(password, username, 2000, 32).getDK();
                    System.out.println(sKey);
                    //Paragwgi tou authHash
                    String authHash = toHex(new PBKDF2(toHex(sKey.getEncoded()), password, 1000, 32).getDK().getEncoded());
                    
                    String digest = "<"+username+","+authHash+">";
                    
                    //Apothikeuei to zeugos
                    saveUsersDigest(digest);
                    
                    String directoriesPath = "Folders/Directories";
                    
                    //Ftiaxneis tous fakelous an den uparxoun
                    File dir = new File(directoriesPath);
                    if (!(dir.exists() && dir.isDirectory())) {
                        dir.mkdir();
                    }
                    File userDir = new File(directoriesPath+"/"+username);
                    userDir.mkdir();
                    
                    msg2L.setText("Έγγραφή επιτυχής.");
                    msg2L.setFont(new Font("Tahoma", Font.ITALIC | Font.BOLD, 15));
                    msg2L.setForeground(Color.green);
                    msg2L.setVisible(true);
                    passwordF.setText("");
                    nusernameF.setText("");
                    npasswordF.setText("");
                    npassword2F.setText("");
                }catch(Exception ex){
                    passwordF.setText("");
                    npasswordF.setText("");
                    npassword2F.setText("");
                    msg2L.setForeground(Color.red);
                    msg2L.setFont(new Font("Tahoma", Font.ITALIC, 13));
                    msg2L.setText(ex.getMessage());
                    msg2L.setVisible(true);
                }
                
            }
        });
        
        Container pane = frame.getContentPane();
        pane.setLayout(null);
        pane.setBackground(Color.ORANGE.darker());
        
        pane.add(loginL);
        pane.add(usernameL);
        pane.add(usernameF);
        pane.add(passwordL);
        pane.add(passwordF);
        pane.add(loginB);
        pane.add(msgL);
        pane.add(registerL);
        pane.add(nusernameL);
        pane.add(nusernameF);
        pane.add(npasswordL);
        pane.add(npasswordF);
        pane.add(npassword2L);
        pane.add(npassword2F);
        pane.add(registerB);
        pane.add(msg2L);
        
        setIcon(frame,"locker.png");
        frame.setSize(700, 500);
        frame.setResizable(false);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }
    
    public void showOptionsGUI(String username){
        String userHomePath = "Folders/Directories/"+username;
        JFrame frame = new JFrame("Files Vault");
        
        JLabel messageL = new JLabel();
        messageL.setBounds(420, 400, 220, 30);
        messageL.setFont(new Font("Tahoma", Font.BOLD, 14)); 
        messageL.setForeground(Color.white);
        
        JLabel loginL = new JLabel("Δυνατότητες:");
        loginL.setBounds(60, 50, 200, 20);
        loginL.setFont(new Font("Tahoma", Font.BOLD, 19));
        loginL.setForeground(Color.white);
        
        JButton addFileB = new JButton("Προσθήκη αρχείου");
        addFileB.setBounds(110, 100, 220,30);
        addFileB.setForeground(Color.white);
        addFileB.setBackground(Color.black);
        
        
        DefaultListModel  model = new DefaultListModel();
        JLabel listFilesL = new JLabel("Λίστα αρχείων:");
        listFilesL.setBounds(400, 50, 200, 20);
        listFilesL.setFont(new Font("Tahoma", Font.BOLD, 19));
        listFilesL.setForeground(Color.white);

        //vlepei pia arxeia uparxoun ston fakelo tou xristi
        File userDir = new File(userHomePath);
        File[] files = userDir.listFiles(new TextFileFilter());
        //kai ta thetei ola ws kwdikopoihmena
        for(int i=0; i<files.length;i++){
            isEncrypted.put(files[i].getName(), Boolean.TRUE);
        }

        JList filesList = new JList();
        filesList.setModel(model);
        for(File f : files){
            model.addElement(f);
        }
        filesList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        filesList.setLayoutOrientation(JList.VERTICAL);
        filesList.setCellRenderer(new FileRenderer(true));
        JScrollPane filesSP = new JScrollPane(filesList);
        filesSP.setBounds(400, 80, 250, 300);
        
        //Edw prostithontai kainourgia arxeia
        addFileB.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                messageL.setVisible(false);
                JFileChooser chooser = new JFileChooser();
                int returnValue = chooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = chooser.getSelectedFile();
                    new AESFileEncryption().encrypt(selectedFile, userHomePath, sKey);
                    File[] files = userDir.listFiles(new TextFileFilter());
                    isEncrypted.put(selectedFile.getName()+".safe", Boolean.TRUE);
                    model.removeAllElements();
                    for(File f : files){
                        model.addElement(f);
                    }
                    messageL.setText("Το αρχείο κωδικοποιήθηκε.");
                    messageL.setVisible(true);
                }    
            }
        });
        
        JButton encOrDec = new JButton("Κρυπτογράφηση/Αποκρυπτογράφηση");
        encOrDec.setBounds(110, 200, 220, 30);
        encOrDec.setForeground(Color.white);
        encOrDec.setBackground(Color.black);
        
        //Edw ginetai kwdikopoihsh h apokodikopoihsh analoga ti xreiazetai
        encOrDec.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                File selectedFile = (File)filesList.getSelectedValue();
                System.out.println(selectedFile.getName());
                if(isEncrypted.get(selectedFile.getName())){
                    new AESFileEncryption().decrypt(selectedFile, userHomePath, sKey);
                    int index = selectedFile.getName().lastIndexOf(".safe"); 
                    isEncrypted.put(selectedFile.getName().substring(0, index), Boolean.FALSE);//Afairw to .safe
                    messageL.setText("Το αρχείο αποκωδικοποιήθηκε.");
                    messageL.setVisible(true);
                }else{
                    new AESFileEncryption().encrypt(selectedFile, userHomePath, sKey);
                    isEncrypted.put(selectedFile.getName()+".safe", Boolean.TRUE); //vazw to .safe
                    messageL.setText("Το αρχείο κωδικοποιήθηκε.");
                    messageL.setVisible(true);
                }
                File[] files = userDir.listFiles(new TextFileFilter());
                model.removeAllElements();
                for(File f : files){
                    model.addElement(f);
                }    
            }
        });
        
        JButton openFileB = new JButton("Άνοιγμα αρχείου");
        openFileB.setBounds(110, 300, 220, 30);
        openFileB.setForeground(Color.white);
        openFileB.setBackground(Color.black);
        
        //Edw anoigei to arxeio me to default programm
        openFileB.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                File selectedFile = (File)filesList.getSelectedValue();
                
                if(selectedFile!=null){
                    try {
                        Desktop desktop = Desktop.getDesktop();
                        desktop.open(selectedFile);
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }     
            }
        });

        Container pane = frame.getContentPane();
        pane.setLayout(null);
        pane.setBackground(Color.ORANGE.darker());
        
        pane.add(messageL);
        pane.add(listFilesL);
        pane.add(filesSP);
        pane.add(loginL);
        pane.add(addFileB);
        pane.add(encOrDec);
        pane.add(openFileB);
        
        
        frame.setSize(700, 500);
        frame.setResizable(false);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
        //Otan kleinei trexei tin encryptAll gia na ta kwdikopoihsei ola osa einai apokwdikopoihmena
        frame.addWindowListener(new WindowListener() {
            @Override
            public void windowOpened(WindowEvent e) {}
            @Override
            public void windowClosing(WindowEvent e) {
                System.out.println("Closing..");encryptAll(userHomePath);}
            @Override
            public void windowClosed(WindowEvent e) {}
            @Override
            public void windowIconified(WindowEvent e) {}
            @Override
            public void windowDeiconified(WindowEvent e) {}
            @Override
            public void windowActivated(WindowEvent e) {}
            @Override
            public void windowDeactivated(WindowEvent e) {}
        });
    }
    
    public void encryptAll(String userHomePath){
        try{
        System.out.println("Encrypting all unencrypted files..");
        File userDir = new File(userHomePath);
        File[] files = userDir.listFiles(new TextFileFilter());
        for(int i=0;i<files.length;i++){
                if(!isEncrypted.get(files[i].getName())){
                    System.out.println("Encrypting: "+files[i].getName());
                    new AESFileEncryption().encrypt(files[i], userHomePath, sKey);
                    System.out.println("Done.");
                }
        }
        System.out.println("Encryption successfull.");
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    
    //Apothikeuei to zeugos (username,authHash) kwdikopoihmeno se RSA2048
    public boolean saveUsersDigest(String digest){
        final String dirpath = "Folders/Digests";
        final String filepath = dirpath+"/digests.data";
        ObjectOutputStream out = null;
        try{
            File dfdir = new File(dirpath);
            File dfile = new File(filepath);
            if (!(dfdir.exists() && dfdir.isDirectory())) {
                dfdir.mkdir();
            }
            if ((dfile.exists())) {
                out = new AppendableObjectOutputStream (new FileOutputStream (dfile, true));
            }else{
                out = new ObjectOutputStream (new FileOutputStream (dfile));
            }
            RSA2048 RSA2048 = new RSA2048();
            String digestEncrypted = toHex(RSA2048.encrypt(digest));
            out.writeObject(new Digest(digestEncrypted));
            out.flush();
            out.close();
            return true;
        }catch(Exception ex){
            Logger.getLogger(FileCrypt.class.getName()).log(Level.SEVERE, null, ex);
        }finally{
            try{
                if (out != null){
                    out.close ();
                }
            }catch(Exception ex){}
        return false;
        }
    }
    
    //Fortwnei to zeugos (username,authHash)
    public boolean loadUsersDigest(String username){
        boolean found = false;
        File dfile = new File ("Folders/Digests/digests.data");
        Digest digest;
        if (dfile.exists ()){
            ObjectInputStream in;
            try{
                in = new ObjectInputStream (new FileInputStream (dfile));
                while((digest = (Digest)in.readObject()) != null){
                    RSA2048 RSA2048 = new RSA2048();
                    String digestDecrypted = RSA2048.decrypt(fromHex(digest.toString()));
                    String digestParts[] = digestDecrypted.split("<|\\,|\\>"); 
                    if(digestParts[1].equals(username)){
                        this.digest = digest;
                        found = true;
                        break;
                    }
                }
                in.close();
            }catch(EOFException ex){}catch (IOException | ClassNotFoundException ex) {
                Logger.getLogger(FileCrypt.class.getName()).log(Level.SEVERE, null, ex);
            }  
        }
        return found;

    }   
    
    public void setSKey(SecretKey sKey){
        this.sKey = sKey;
    }
    
    public void setIcon(JFrame frame,String iconpath ){
        URL path = ClassLoader.getSystemResource(iconpath);
        if(path!=null) {
             ImageIcon img = new ImageIcon(path);
             frame.setIconImage(img.getImage());
        }
    }
    
    public static void main(String[] args){
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                File ffdir = new File("Folders");
                if (!(ffdir.exists() && ffdir.isDirectory())) {
                    ffdir.mkdir();
                }
                new FileCrypt().showLoginGUI();
            }
        });
    }
    
    //I methodos gia sugkrisi twn duo bytes arrays 
    //Einai pio argi apo tin Arrays.equal kai giauto ti protimisa
    //Source : https://crackstation.net/hashing-security.htm
    private static boolean slowEquals(byte[] a, byte[] b){
        int diff = a.length ^ b.length;
        for(int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
    
     //I methodoi gia metatropi byte array apo kai se 16adiko
    private byte[] fromHex(String hex){
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length ;i++)
        {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
    
    private String toHex(byte[] array){
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }
    
    //Αυτη η κλαση επιτρεπει την εγγραφη ενος αντικειμενου σε ενα αρχειο κανοντας το append
    private static class AppendableObjectOutputStream extends ObjectOutputStream {
        public AppendableObjectOutputStream(OutputStream out) throws IOException {
          super(out);
        }
        @Override
        protected void writeStreamHeader() throws IOException {}
    }
    
    //To filtro gia na vrei mono ta arxeia
    class TextFileFilter implements FileFilter {
        public boolean accept(File file) {
            return !file.isDirectory();
        }
    }
    
    class FileRenderer extends DefaultListCellRenderer {

    private boolean pad;
    private Border padBorder = new EmptyBorder(3,3,3,3);

    //Custom FileRenderer
    FileRenderer(boolean pad) {
        this.pad = pad;
    }

    @Override
    public Component getListCellRendererComponent(
        JList list,
        Object value,
        int index,
        boolean isSelected,
        boolean cellHasFocus) {

        Component c = super.getListCellRendererComponent(
            list,value,index,isSelected,cellHasFocus);
        JLabel l = (JLabel)c;
        if(value.getClass().getCanonicalName().equals("java.lang.String")){
            l.setText((String)value);
        }else{
            File f = (File)value;
            l.setText(f.getName());
            l.setIcon(FileSystemView.getFileSystemView().getSystemIcon(f));
        } 
        if (pad) {
            l.setBorder(padBorder);
        }

        return l;
    }
}
}
