package ProtocolPackets;

import Utils.ColorPrint;
import Utils.Serializer;
import java.io.Serializable;
import java.util.*;

/**
 *
 * @author icsd12015
 */
public class SIP_Packet implements Serializable {

    static final long serialVersionUID = 1942187908423143633L;

    //Oi tupoi twn methodwn (pou xrisimopoioume)
    public static enum Method {

        ACK,
        REGISTER,
        INVITE,
        RESPONSE
    }

    //Oi tupoi twn Responce codes (pou xrisimopoioume)
    public static class RESPONCE_CODES {

        public static final int TRYING = 100, RINGING = 180;
        public static final int OK = 200;
        public static final int UNAUTHORIZED = 401, NOT_FOUND = 404, PROXY_AUTHENTICATION_REQUIRED = 407;
    }

    //HashMap me to onoma twn codes autwn
    public static HashMap<Integer, String> codes = new HashMap() {
        {
            put(100, "Trying");
            put(180, "Ringing");
            put(200, "OK");
            put(401, "Unauthorized");
            put(404, "Not Found");
            put(407, "Proxy Authentication Required");
        }
    };

    //Ta pedia twn headers tou paketou
    private final Method method; //τυπος μηνυματος (για διαχειρηση τους απο τα handlers
    private int code;

    private final String FromHeader;
    private String From_name;
    private String From_tag;
    private final ArrayList<String[]> ViaHeaders;
    private final String ToHeader;
    private String To_name;
    private String To_tag;
    private String CallID;
    private int maxForwards;
    private String RecordRoute;
    private String Contact;

    private int CSeq;
    private Method CSeqMethod;

    private boolean hasAuthenticationHeader = false;
    private String Authencticate_realm, Authencticate_algorithm, Authencticate_nonce;
    private boolean hasAuthorizationHeader = false;
    private String Authorization_realm, Authorization_nonce, Authorization_uri, Authorization_responce, Authorization_username, Authorization_cnonce;

    //Gia to content (de xrisimopoihtike)
    private String ContentType;
    private final int ContentLength;
    private String Content;

    //Dimiourgia SIP paketou Methodou
    public SIP_Packet (Method method, String from, String to) {
        this.method = method;
        this.maxForwards = (method == Method.RESPONSE ? 0 : 70);
        this.FromHeader = from;
        this.ViaHeaders = new ArrayList<>();
        this.From_name = getNameFromAddress(from);
        this.ToHeader = to;
        this.To_name = getNameFromAddress(to);
        this.ContentLength = 0;
        this.CSeq = 1;
    }

    //Dimiourgia SIP paketou Methodou me via header
    public SIP_Packet (Method method, String from, String[] via, String to) {
        this.method = method;
        this.maxForwards = (method == Method.RESPONSE ? 0 : 70);
        this.FromHeader = from;
        this.ViaHeaders = new ArrayList<>();
        this.ViaHeaders.add(via);
        this.From_name = getNameFromAddress(from);
        this.ToHeader = to;
        this.To_name = getNameFromAddress(to);
        this.ContentLength = 0;
        this.CSeq = 1;
    }

    //Dimiourgia SIP paketou Responce me code kai via header
    public SIP_Packet (int code, String from, String[] via, String to) {
        this.method = Method.RESPONSE;
        this.maxForwards = 0;
        this.code = code;
        this.FromHeader = from;
        this.ViaHeaders = new ArrayList<>();
        this.ViaHeaders.add(via);
        this.From_name = getNameFromAddress(from);
        this.ToHeader = to;
        this.To_name = getNameFromAddress(to);
        this.ContentLength = 0;
        this.CSeq = 1;
    }

    //Dimiourgia SIP paketou Responce me code
    public SIP_Packet (int code, String from, String to) {
        this.method = Method.RESPONSE;
        this.maxForwards = 0;
        this.code = code;
        this.FromHeader = from;
        this.ViaHeaders = new ArrayList<>();
        this.From_name = getNameFromAddress(from);
        this.ToHeader = to;
        this.To_name = getNameFromAddress(to);
        this.ContentLength = 0;
        this.CSeq = 1;
    }

    //Gia prosthiki Via header
    public void addVia (String[] via) {
        this.ViaHeaders.add(via);
    }

    //Gia epistrofi onomatos apo address (vasi username) gia tin ektipwsi
    private String getNameFromAddress (String address) {
        address = address.substring(0, address.indexOf("@"));
        String temp = "" + address.toUpperCase().charAt(0);
        temp = temp.concat(address.substring(1, address.length()));
        return temp;
    }

    //Epistrofi bytes tou antikeimenou
    public byte[] getBytes () {
        return Serializer.serialize(this);
    }

    @Override
    public String toString () {
        String string = (this.method == Method.RESPONSE ? "" : this.method + " ")
                + "sip:" + this.ToHeader.toLowerCase() + " SIP/2.0 "
                + (this.method == Method.RESPONSE ? this.code + " " + this.codes.get(code) : "");
        for (int i = this.ViaHeaders.size() - 1; i >= 0; i--) {
            String[] via = this.ViaHeaders.get(i);
            if (via.length == 2) {
                string += ("\nVia: SIP/2.0/TCP " + via[0] + ";branch=" + via[1]);
            } else if (via.length == 3) {
                string += ("\nVia: SIP/2.0/TCP " + via[0] + ";branch=" + via[1] + ";received=" + via[2]);
            }
        }
        string += ((this.maxForwards == 0 ? "" : "\nMax-Forwards: " + this.maxForwards)
                   + "\nFrom: " + this.From_name + " <sip:" + this.FromHeader.toLowerCase() + ">" + (this.From_tag == null ? "" : ";tag=" + this.From_tag)
                   + "\nTo: " + this.To_name + " <sip:" + this.ToHeader.toLowerCase() + ">" + (this.To_tag == null ? "" : ";tag=" + this.To_tag)
                   + "\nCall-ID: " + this.CallID + this.FromHeader.substring(this.FromHeader.indexOf("@"))
                   + "\nCSeq: " + this.CSeq + " " + (this.CSeqMethod == null ? this.method : this.CSeqMethod)
                   + "\nContent-Length: " + this.ContentLength);
        if (this.hasAuthenticationHeader) {
            string += "\nProxy-Authenticate: Digest "
                    + "\n\trealm=\"" + this.Authencticate_realm + "\", "
                    + "\n\tqop=\"auth\", "
                    + "\n\tnonce=\"" + this.Authencticate_nonce + "\", "
                    + "\n\talgorithm=\"" + this.Authencticate_algorithm + "\"";
        }
        if (this.hasAuthorizationHeader) {
            string += "\nProxy-Authorization: Digest "
                    + "\n\tusername=\"" + this.Authorization_username + "\", "
                    + "\n\trealm=\"" + this.Authorization_realm + "\", "
                    + "\n\tnonce=\"" + this.Authorization_nonce + "\", "
                    + "\n\tcnonce=\"" + this.Authorization_cnonce + "\""
                    + "\n\tresponce=\"" + this.Authorization_responce + "\"";
        }
        string += ((this.ContentLength == 0 ? ""
                    : "\nContent-Type: " + this.ContentType
                    + "\nContent: " + this.Content));

        return string;
    }

    //Emfanisi me xrwmata me ti klasi ColorPrint (idio me toString aplws me xrwma)
    public void colorPrint () {
        String string = ColorPrint.ANSI_PURPLE + (this.method == Method.RESPONSE ? "" : this.method + " ")
                + "sip:" + this.ToHeader.toLowerCase() + " SIP/2.0 "
                + (this.method == Method.RESPONSE ? this.code + " " + this.codes.get(code) : "") + ColorPrint.ANSI_RESET;
        for (int i = this.ViaHeaders.size() - 1; i >= 0; i--) {
            String[] via = this.ViaHeaders.get(i);
            if (via.length == 2) {
                string += (ColorPrint.ANSI_BLUE + "\nVia:" + ColorPrint.ANSI_RESET + " SIP/2.0/TCP " + via[0] + ";branch=" + via[1]);
            } else if (via.length == 3) {
                string += (ColorPrint.ANSI_BLUE + "\nVia:" + ColorPrint.ANSI_RESET + " SIP/2.0/TCP " + via[0] + ";branch=" + via[1] + ";received=" + via[2]);
            }
        }
        string += (ColorPrint.ANSI_BLUE + (this.maxForwards == 0 ? "" : "\nMax-Forwards: " + ColorPrint.ANSI_RESET + this.maxForwards)
                   + ColorPrint.ANSI_BLUE + "\nFrom: " + ColorPrint.ANSI_RESET + this.From_name + " <sip:" + this.FromHeader.toLowerCase() + ">" + (this.From_tag == null ? "" : ";tag=" + this.From_tag)
                   + ColorPrint.ANSI_BLUE + "\nTo: " + ColorPrint.ANSI_RESET + this.To_name + " <sip:" + this.ToHeader.toLowerCase() + ">" + (this.To_tag == null ? "" : ";tag=" + this.To_tag)
                   + ColorPrint.ANSI_BLUE + "\nCall-ID: " + ColorPrint.ANSI_RESET + this.CallID + this.FromHeader.substring(this.FromHeader.indexOf("@"))
                   + ColorPrint.ANSI_BLUE + "\nCSeq: " + ColorPrint.ANSI_RESET + this.CSeq + " " + (this.CSeqMethod == null ? this.method : this.CSeqMethod)
                   + ColorPrint.ANSI_BLUE + "\nContent-Length: " + ColorPrint.ANSI_RESET + this.ContentLength);
        if (this.hasAuthenticationHeader) {
            string += ColorPrint.ANSI_BLUE + "\nProxy-Authenticate: " + ColorPrint.ANSI_RESET + "Digest "
                    + "\n\trealm=\"" + ColorPrint.ANSI_RESET + this.Authencticate_realm + "\", "
                    + "\n\tqop=" + ColorPrint.ANSI_RESET + "\"auth\", "
                    + "\n\tnonce=\"" + ColorPrint.ANSI_RESET + this.Authencticate_nonce + "\", "
                    + "\n\talgorithm=\"" + ColorPrint.ANSI_RESET + this.Authencticate_algorithm + "\"";
        }
        if (this.hasAuthorizationHeader) {
            string += ColorPrint.ANSI_BLUE + "\nProxy-Authorization: " + ColorPrint.ANSI_RESET + "Digest "
                    + "\n\tusername=\"" + ColorPrint.ANSI_RESET + this.Authorization_username + "\", "
                    + "\n\trealm=\"" + ColorPrint.ANSI_RESET + this.Authorization_realm + "\", "
                    + "\n\tnonce=\"" + ColorPrint.ANSI_RESET + this.Authorization_nonce + "\", "
                    + "\n\tcnonce=\"" + ColorPrint.ANSI_RESET + this.Authorization_cnonce + "\""
                    + "\n\tresponce=\"" + ColorPrint.ANSI_RESET + this.Authorization_responce + "\"";
        }
        string += (this.ContentLength == 0 ? "" : ColorPrint.ANSI_BLUE + "\nContent-Type: " + ColorPrint.ANSI_RESET + this.ContentType
                   + ColorPrint.ANSI_BLUE + ColorPrint.ANSI_RESET + "\nContent: " + this.Content);
        System.out.println(string);
    }

    public String[] removeLastViaHeader () {
        return this.ViaHeaders.remove(ViaHeaders.size() - 1);
    }

    public String[] peekLastViaHeader () {
        return this.ViaHeaders.get(ViaHeaders.size() - 1);
    }

    public void setFromTag (String From_tag) {
        this.From_tag = From_tag;
    }

    public void setToTag (String To_tag) {
        this.To_tag = To_tag;
    }

    public void setCSeqMethod (Method CSeqMethod) {
        this.CSeqMethod = CSeqMethod;
    }

    public void setCallID (String CallID) {
        this.CallID = CallID;
    }

    public void setMaxForwards (int maxForwards) {
        this.maxForwards = this.method == Method.RESPONSE ? 0 : maxForwards;
    }

    public void setCSeq (int CSeq) {
        this.CSeq = CSeq;
    }

    public void setRecordRoute (String route) {
        this.RecordRoute = route;
    }

    public void setAuthenticate (boolean Authenticate) {
        this.hasAuthenticationHeader = Authenticate;
    }

    public void setAuthencticateRealm (String Authencticate_realm) {
        this.Authencticate_realm = Authencticate_realm;
    }

    public void setAuthencticateAlgorithm (String Authencticate_algorithm) {
        this.Authencticate_algorithm = Authencticate_algorithm;
    }

    public void setAuthencticateNonce (String Authencticate_nonce) {
        this.Authencticate_nonce = Authencticate_nonce;
    }

    public void setAuthorization (boolean Authorization) {
        this.hasAuthorizationHeader = Authorization;
    }

    public void setAuthorizationRealm (String realm) {
        this.Authorization_realm = realm;
    }

    public void setAuthorizationNonce (String nonce) {
        this.Authorization_nonce = nonce;
    }

    public void setAuthorizationUri (String uri) {
        this.Authorization_uri = uri;
    }

    public void setAuthorizationResponce (String responce) {
        this.Authorization_responce = responce;
    }

    public void setAuthorizationUsername (String username) {
        this.Authorization_username = username;
    }

    public void setAuthorizationCnonce (String cnonce) {
        this.Authorization_cnonce = cnonce;
    }

    public Method getMethod () {
        return method;
    }

    public int getCode () {
        return code;
    }

    public int getMaxForwards () {
        return maxForwards;
    }

    public String getToHeader () {
        return ToHeader;
    }

    public String getToTag () {
        return To_tag;
    }

    public String getFromHeader () {
        return FromHeader;
    }

    public String getFromHeaderTag () {
        return From_tag;
    }

    public ArrayList<String[]> getViaHeaders () {
        return ViaHeaders;
    }

    public String getCallID () {
        return CallID;
    }

    public int getCSeq () {
        return CSeq;
    }

    public Method getCSeqMethod () {
        return this.CSeqMethod;
    }

    public String getFromHeaderName () {
        return From_name;
    }

    public String getToHeaderName () {
        return To_name;
    }

    public boolean hasAuthenticationHeader () {
        return hasAuthenticationHeader;
    }

    public String getAuthencticateRealm () {
        return Authencticate_realm;
    }

    public String getAuthencticateAlgorithm () {
        return Authencticate_algorithm;
    }

    public String getAuthencticateNonce () {
        return Authencticate_nonce;
    }

    public boolean hasAuthorizationHeader () {
        return hasAuthorizationHeader;
    }

    public String getAuthorizationRealm () {
        return Authorization_realm;
    }

    public String getAuthorizationNonce () {
        return Authorization_nonce;
    }

    public String getAuthorizationUri () {
        return Authorization_uri;
    }

    public String getAuthorizationResponce () {
        return Authorization_responce;
    }

    public String getAuthorizationUsername () {
        return Authorization_username;
    }

    public String getAuthorizationCnonce () {
        return Authorization_cnonce;
    }

    public String getContentType () {
        return ContentType;
    }

    public int getContentLength () {
        return ContentLength;
    }

    public String getContent () {
        return Content;
    }

}
