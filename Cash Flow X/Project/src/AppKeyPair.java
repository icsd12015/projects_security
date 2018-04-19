
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

//Αυτη η κλαση αφορα το ζευγος κλειδιων της εφαρμογης για την ασυμμετρη κρυπτογραφηση
public class AppKeyPair {

    //Κλειδια εφαρμογης σε κωδικοποιηση Base64 δηλωμενα ως σταθερες στο κωδικα 
    //(Το αρχειο με το pulic σε περιπτωση που χαθει το ξαναγραφει η εφαρμογη γιαυτο αποθηκευεται και αυτο)
    private static final String PUBLIC_KEY_STRING = "MIIBIjANBgkqhkiG9w0BAQEFAAO"
            + "CAQ8AMIIBCgKCAQEA18pU5ZpsuqeOSiF96m9gNnAuF1JR7KCfPTBJmQqxBv9INyQv"
            + "y6tA647yOvb4nkMFm4hpMmr225tyl05NX8KDJ3V9dRlGZvdUqrU4wZdfpGtettcHF"
            + "FPuMSLemArKKjYns1WLD8umNfa8o+/nAJ579QKWQGxTaqzX718kM8tCo7wehihwQ9"
            + "lhZO58HbXOV/L4xosJgRgISfmRrVCvQCQwJtMqEWu0/CREvfpr+F1jqaRowOQmJlt"
            + "egeMP/Hihx5CoKJvvxdlpOAtmImzSG4nbixzshq+xtMxQCqUiZfO7IzX0fj5m6fbo"
            + "biXvIInRNzgfqDErEo3Mil+tVoXytW3f6QIDAQAB";

    private static final String PRIVATE_KEY_STRING = "MIIEvQIBADANBgkqhkiG9w0BAQ"
            + "EFAASCBKcwggSjAgEAAoIBAQDXylTlmmy6p45KIX3qb2A2cC4XUlHsoJ89MEmZCrE"
            + "G/0g3JC/Lq0DrjvI69vieQwWbiGkyavbbm3KXTk1fwoMndX11GUZm91SqtTjBl1+k"
            + "a1621wcUU+4xIt6YCsoqNiezVYsPy6Y19ryj7+cAnnv1ApZAbFNqrNfvXyQzy0Kjv"
            + "B6GKHBD2WFk7nwdtc5X8vjGiwmBGAhJ+ZGtUK9AJDAm0yoRa7T8JES9+mv4XWOppG"
            + "jA5CYmW16B4w/8eKHHkKgom+/F2Wk4C2YibNIbiduLHOyGr7G0zFAKpSJl87sjNfR"
            + "+Pmbp9uhuJe8gidE3OB+oMSsSjcyKX61WhfK1bd/pAgMBAAECggEAN+z3Tb5U+Zcd"
            + "WHcPpCeTXuh5+Y9bLiF+w6P1HxXXRYH53FijjnxmyeX1P3TsgE/Mbz/OS8PPEKFb9"
            + "HzVrsDBrwNTLXsMdPka11c6S2oI3pr5JBfcfNc3v0JTQEJjnMcGSQMdlE1qWUgGId"
            + "K2IsHwTFKMUEwC3n3HRQF6Z3YBYl+P0jDHBsXDzasA4ZAKT5ujrfCuW1s3OXEo0le"
            + "Rai0LhURcRcSoUyoWnX6IiguUmrP0UYP/wwklHR6VhZDNBq/g6otmpW0dIGD3zXo/"
            + "Lca+JnSOpqlM7RxNNhvAL80FIO2RRWDZletqe4MHSEbO/Ht/PFnlO5bt11/qiEaHh"
            + "viu5QKBgQD6el2ia8uz8E5KUm5v1+/E4c7655S+EA1BY9IEaMiMAmwvA+zB9FRRau"
            + "ZLe3iVTzQxU9yWKoSIIKOQWGNya0+WXIbj5vcbRCTKg+fNiR9DgaNItHiuD+NTvrK"
            + "c7nsQExbl0cjfZYvc/olvzZWPyufjqkDIaPCciczH9dKqIs5H6wKBgQDcjDKaPmlO"
            + "sMvs76JJPRP1ZU83fWEwJD5cvoJF88rJnzJXN4DBr+Pwf0xI/jX1rBNbWcrwLGsGN"
            + "v2Ih/+feXr/Zx/Vy2JhCqxhrN4VjtC5RJ9hAM22JvbJaDFtjdH4uvvFPjwexPyyEw"
            + "+PoKJsz7TveRs94ReRD+fjnIVJTcF2ewKBgQCrSKJfP3e9RMdE67m5oeDEseXojhS"
            + "ZJEDsRmaHvV/m3oE8ZWKx/3LpekChvX1oHRGD6eUei1S2AhvXyZm31MpH+F4F2xt/"
            + "+clu82TAmNRYRX5zaXZdEWBTFETwK+TbyTIPVrYWjkpmhWlWmy97dTW96d8DLT/cz"
            + "B7NXr0Au2x0oQKBgD11mDhhggkavYlGciwEqEYvODcXanj28KX5tOX3fSBYi7fAUN"
            + "IoyNVhNAn3RWQz0qUXTbVGO4Dc3CQq+fIf8UWxIC784Wp3hfgmKzFIviOS2vM2PR0"
            + "wmH8h2PxVlBjDSpv5rtlIPb8GDsUQl5LJAvvk/NFuo5maHB3SpVX7JBl3AoGAaipX"
            + "uDCYcSbk6WP5d/6G05ZedJ5SVcs/OVtolMuv+4k8nwKuNgQcZXxFA5Z7Kg15e+gFI"
            + "NeZ9NP+RbUZdRxePVNn0UY9OmrIyQCKoh9VnZwdYMIa+kO2WTqZsKyLgfZtCWdAZo"
            + "+QJWKy/gdLFnJhPlmpU20fWp9hX/qM1Fi175w=";

    //Ετσι δημιουργηθηκαν το ζευγος κλειδιων

    public static void main(String[] args) {
        try {
            KeyPair keys = generateKeyPair();
            System.out.println("Public:\n" + Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()));
            System.out.println("Private:\n" + Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded()));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AppKeyPair.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); //Αλγοριθμος RSA
        keyGen.initialize(2048); //Μεγεθος Κλειδιων
        return keyGen.generateKeyPair();
    }

    public static String getPrivate() {
        return AppKeyPair.PRIVATE_KEY_STRING;
    }

    public static String getPublic() {
        return AppKeyPair.PUBLIC_KEY_STRING;
    }
}
