//I klasi gia eggrafi twn zeugwn sto arxeio
import java.io.Serializable;

public class Digest implements Serializable{
    private String digest;
    
    public Digest(String digest){
        this.digest = digest;
    }
    
    @Override
    public String toString(){
        return digest;
    }
}
