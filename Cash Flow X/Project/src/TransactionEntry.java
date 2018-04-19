import java.util.UUID;

//Κλαση αναπαραστασης Λογιστικων Εγγραφων
public class TransactionEntry {
    public final static int INCOME = 1;
    public final static int OUTCOME = 2;
    
    private String ammount;
    private String description;
    private String date;
    private int type;
    private String id;

    public TransactionEntry(String date, String ammount,String description, int type) {
        this.ammount = ammount;
        this.description = description;
        this.date = date;
        this.type = type;
        this.id = UUID.randomUUID().toString().split("-")[4].toUpperCase(); //Δημιουργια κωδικου με java.util.UUID
    }
    
    public TransactionEntry(String id,String date, String ammount,String description, int type) {
        this.ammount = ammount;
        this.description = description;
        this.date = date;
        this.type = type;
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public String getAmmount() {
        return ammount;
    }

    public String getDescription() {
        return description;
    }

    public String getDate() {
        return date;
    }

    public int getType() {
        return type;
    }

    @Override
    public String toString() {
        return "Transcaction: #"+id+".\nType: "+type+".\nDate: "+date+".\nAmmount: "+ammount+".\nDescription: "+description+".\n\n";
    }
    
    
}
