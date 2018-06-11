import org.json.JSONArray;
import org.json.JSONObject;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Seehsam {

    /**
     * Generiert ein RSA Schlüsselpaar mit einem Public und Private-Key
     * Schlüssellänge: 512
     * @return JSONObject with public and private key
     */
    private static JSONObject generateKeyPair() throws Exception{
        KeyPair keyPair;
        KeyPairGenerator keygenerator;
        JSONObject JSONkeyPairObject = new JSONObject();
        try {
            keygenerator = KeyPairGenerator.getInstance("RSA");
            keygenerator.initialize(512);
            keyPair = keygenerator.genKeyPair();
            byte[] encodedPrivateKey = keyPair.getPrivate().getEncoded();
            String b64private = Base64.getEncoder().encodeToString(encodedPrivateKey);
            JSONkeyPairObject.put("private",b64private);
            byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
            String b64public = Base64.getEncoder().encodeToString(encodedPublicKey);
            JSONkeyPairObject.put("public",b64public);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return JSONkeyPairObject;
    }

    /**
     * Generiert einen zufälligen Documentkey
     * Schlüssellänge 256 Bit
     * @return  Zufälliger Base64 String
     */
    private static String generateRandomDocumentKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 256;
        keyGenerator.init(keyBitSize, secureRandom);
        Key secretKey = keyGenerator.generateKey();
        byte[] b = secretKey.getEncoded();
        BASE64Encoder myEncoder = new BASE64Encoder();
        return myEncoder.encode(b);
    }


    /**
     * Verschluesselt den DocumentKey mit allen Public-Keys aus dem hasAccess Feld
     *
     * @param documentKey Schlüssel der den Vertrag verschlüsselt
     * @param hasAcc      JSONArray mit allen berechtigten Nutzern
     * @return BASE64 String
     */
    private String encryptDocumentKey(String documentKey, JSONArray hasAcc) throws Exception {
        String geheim;
        JSONArray docKeys = new JSONArray();
        BASE64Encoder myEncoder = new BASE64Encoder();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        for (int i = 0; i < hasAcc.length(); i++) {
            // Verschluesseln
            Cipher cipher = Cipher.getInstance("RSA");
            //Convert Base64 Public-Key String to PublicKey
            String base64public = hasAcc.getJSONObject(i).getJSONObject("encryption").get("public").toString();
            byte[] publicBytes = Base64.getDecoder().decode(base64public);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicBytes);
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
            //Encrypt
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encrypted = cipher.doFinal(documentKey.getBytes());
            // bytes zu Base64-String konvertieren
            geheim = myEncoder.encode(encrypted);
            JSONObject docKey = new JSONObject();
            docKey.put(hasAcc.getJSONObject(i).get("name").toString(), geheim);
            docKeys.put(docKey);
        }
        return myEncoder.encode(docKeys.toString().getBytes());
    }

    /**
     * Entschluesselt einen BASE64 kodierten DocumentKey mittels dem user und dessen Private-Key
     *
     * @param documentKeyEnc BASE64 kodierter Text
     * @param user JSONObject eines Users
     * @return DocumentKey im Klartext
     */
    private String decryptDocumentKey(String documentKeyEnc, JSONObject user) throws Exception {
        String username = user.get("name").toString();
        String encDocKeyUser;
        byte[] plainDocKey;
        byte[] cipherData;
        String finalCiper = null;
        BASE64Decoder myDecoder = new BASE64Decoder();
        byte[] plainDoc = myDecoder.decodeBuffer(documentKeyEnc);
        JSONArray jsa = new JSONArray(new String(plainDoc));
        for (int i = 0; i < jsa.length(); i++) { //Sort for name!
            if(jsa.getJSONObject(i).has(username)) {
                encDocKeyUser  = jsa.getJSONObject(i).get(username).toString();
                plainDocKey = myDecoder.decodeBuffer(encDocKeyUser);
                Cipher cipher = Cipher.getInstance("RSA");
                //Convert Base64 Public-Key String to PublicKey
                String base64private = user.getJSONObject("encryption").get("private").toString();
                byte[] privateBytes = Base64.getDecoder().decode(base64private);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(spec);
                cipher.init(Cipher.DECRYPT_MODE, privKey);
                cipherData = cipher.doFinal(plainDocKey);
                finalCiper = new String(cipherData);
            }
        }
        return finalCiper;
    }

    /**
     * SecretKeySpecs erzeugt einen Key aus einem String
     * @param myKey String aus dem ein Key erzeugt werden soll
     * @return secretKey
     */
    private static SecretKeySpec setKey(String myKey) {
        MessageDigest sha;
        byte[] key;
        SecretKeySpec secretKey;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
            return secretKey;
        }
        catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Verschlüsselt einen String mittels AES
     * @param strToEncrypt  String der verschlüsselt werden soll
     * @param secret    passphrase zum verschlüsseln
     * @return String Cipher
     */
    private String encryptString(String strToEncrypt, String secret) {
        try
        {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, setKey(secret));
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    /**
     * Entschlüsselt einen String mittels AES
     * @param strToDecrypt  String der entschlüsselt werden soll
     * @param secret    passphrase zum entschlüsseln
     * @return
     */
    private String decryptString(String strToDecrypt, String secret) {
        try
        {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, setKey(secret));
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }



    public static void main(String[] args) throws Exception {
        //Init 2 User -> Peter & Fred
        JSONObject peter = new JSONObject();
        JSONObject fred = new JSONObject();
        JSONObject petKeyPair = generateKeyPair();
        peter.put("encryption" , petKeyPair);
        peter.put("name" , "Peter");
        JSONObject freKeyPair = generateKeyPair();
        fred.put("encryption" , freKeyPair);
        fred.put("name" , "Fred");

        //Init data
        JSONArray data = new JSONArray();
        JSONObject secretStuff = new JSONObject();
        secretStuff.put("cash","10000 Euro");
        secretStuff.put("time", 2);
        JSONObject secondSecretStuff = new JSONObject();
        secondSecretStuff.put("log","This is a long string with informations");
        secondSecretStuff.put("protocol","This is the protocol, im very happy");
        data.put(secretStuff);
        data.put(secondSecretStuff);

        //Init has access
        JSONArray hasAccess = new JSONArray();
        hasAccess.put(peter);
        hasAccess.put(fred);

        //Init Seehsam
        Seehsam sam = new Seehsam();

        //Encrypt Private-Key
        System.out.println("PrivateKey Peter in Base64: ");
        System.out.println(peter.getJSONObject("encryption").get("private").toString());
        System.out.println();

        //Encrypted Private-Key
        String encPriv = sam.encryptString(peter.getJSONObject("encryption").get("private").toString(),"password");
        System.out.println("Encrypted PrivateKey Peter in Base64: ");
        System.out.println(encPriv);
        System.out.println();

        //Decrypted Private-Key
        System.out.println("Decrypted PrivateKey Peter in Base64: ");
        System.out.println(sam.decryptString(encPriv,"password"));

        //generate documentKey
        String randomDoc = generateRandomDocumentKey();

        //Plain documentKey
        System.out.println("Documentkey Klartext: ");
        System.out.println(randomDoc);
        System.out.println();

        //Encrypted Documentkey hasAccess
        String encDocKey =  sam.encryptDocumentKey(randomDoc,hasAccess);
        System.out.println("Encrypted Documentkey in Base64: ");
        System.out.println(encDocKey);
        System.out.println();

        //Decrypted DocumentKey Fred
        String decDocKeyFred = sam.decryptDocumentKey(encDocKey,fred);
        System.out.println();
        System.out.println("Decrypted DocumentKey Fred: ");
        System.out.println(decDocKeyFred);

        //DocumentKey entschlüsseln Peter
        String decDocKeyPeter = sam.decryptDocumentKey(encDocKey,peter);
        System.out.println();
        System.out.println("Decrypted DocKeyPeter: ");
        System.out.println(sam.decryptDocumentKey(encDocKey,peter));

        //Plain Data
        System.out.println();
        System.out.println("Plain data: ");
        System.out.println(data);

        //Encrypted data with documentKey Fred
        String dataCipherFred = sam.encryptString(data.toString(),decDocKeyFred);
        System.out.println();
        System.out.println("Encrypted data with documentKey Fred: ");
        System.out.println(dataCipherFred);

        //Encrypted data with documentKey Peter
        String dataCipherPeter = sam.encryptString(data.toString(),decDocKeyPeter);
        System.out.println();
        System.out.println("Encrypted data with documentKey Peter: ");
        System.out.println(dataCipherPeter);

        //Decrypted data Fred
        String plainDataFred = sam.decryptString(dataCipherFred,decDocKeyFred);
        System.out.println();
        System.out.println("Decrypted data Fred: ");
        System.out.println(plainDataFred);

        //Decrypted data Peter
        String plainDataPeter = sam.decryptString(dataCipherPeter,decDocKeyPeter);
        System.out.println();
        System.out.println("Decrypted data Peter: ");
        System.out.println(plainDataPeter);
    }
}