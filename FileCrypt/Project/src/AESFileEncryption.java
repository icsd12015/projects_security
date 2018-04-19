
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;


//Boithise arketa:
//https://gist.githubusercontent.com/dweymouth/11089238/raw/294a2561cf3e3054cf5d4111651fa8c8b7fd75b4/AES.java

public class AESFileEncryption{
    
    public void encrypt(File file,String dirPath,SecretKey key){
        try {
            //pairnei to cipher antikeimeno gia ton algoruthmo AES
            Cipher cipher = Cipher.getInstance("AES"); 
       
            //Orizei ton kryptografima gia kwdikopoihsh
            cipher.init(Cipher.ENCRYPT_MODE, key);  

            //To oustream p tha xrisimopoihsei o CipherOutputStream
            try(FileOutputStream fout = new FileOutputStream(dirPath+"/"+file.getName()+".safe")){

                //To instream
                try(FileInputStream in = new FileInputStream(file)){
                
                    //To CipherOutputStream
                    try(CipherOutputStream out = new CipherOutputStream(fout, cipher)){
                         int read;
                         byte buf[] = new byte[2048];
                         //diavazei to arxeio kai grafei to kwdikopoihmeno keimeno
                         while((read = in.read(buf)) != -1){  
                            out.write(buf, 0, read); 
                         }
                    }
                }
                file.delete();
            } 
        } catch (Exception ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
   
 }
  //Antistoixa
    public void decrypt(File file,String dirPath,SecretKey key){
        
       //Inputstream p tha xrisimopoihsei o CipherInputStream
       try(FileInputStream fin = new FileInputStream(file)){
       
       Cipher cipher = Cipher.getInstance("AES");  
       //Orizei ton kryptografima gia apokwdikopoihsh
       cipher.init(Cipher.DECRYPT_MODE, key); 
       
       //output stream se arxeio xwris tin kataliksi .safe
       int index = file.getName().lastIndexOf(".safe");
       File dest = new File(dirPath+"/"+file.getName().substring(0, index));
       try(FileOutputStream out = new FileOutputStream(dest)){
           
           //To CipherInputStream
           try(CipherInputStream in = new CipherInputStream(fin, cipher)){
               int read;
               byte buf[] = new byte[2048];
               //diavazei to arxeio kai grafei to apokwdikopoihmeno keimeno
               while((read = in.read(buf)) != -1){  
                   out.write(buf, 0, read); 
               }
           }
           out.close();
           file.delete();
       }
       }catch (Exception ex) {
           Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
       }

   }
}
