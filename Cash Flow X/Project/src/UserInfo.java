//Κλαση αναπαραστασης Προφιλ Χρηστη ( οπως αποθηκευεται στο αρχειο των συνοψεων)
public class UserInfo {
    private String fname;
    private String lname;
    private String uname;
    private String saltEncoded;
    private String encryptedDigestEncoded;
    private String keyEncoded;
    
    public UserInfo(String first_name,String last_name,String username,String salt,String digest,String key){
            this.fname = first_name;
        this.lname = last_name;
        this.uname = username;
        this.saltEncoded = salt;
        this.encryptedDigestEncoded = digest;
        this.keyEncoded = key;
    }

    public String getSaltEncoded() {
        return saltEncoded;
    }

    public String getEncryptedDigestEncoded() {
        return encryptedDigestEncoded;
    }

    public String getKeyEncoded() {
        return keyEncoded;
    }

    public String getFname() {
        return fname;
    }

    public String getLname() {
        return lname;
    }

    public String getUname() {
        return uname;
    }


    
    
}
