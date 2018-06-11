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
     * @return RSA KeyPair
     */
    public static JSONObject generateKeyPair() throws Exception{
        KeyPair keyPair = null;
        KeyPairGenerator keygenerator = null;
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
     * @return randomBase64String   Zufälliger Base64 String
     * @throws NoSuchAlgorithmException
     */
    public static String generateRandomDocumentKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 256;
        keyGenerator.init(keyBitSize, secureRandom);
        Key secretKey = keyGenerator.generateKey();
        byte[] b = secretKey.getEncoded();
        BASE64Encoder myEncoder = new BASE64Encoder();
        String randomBase64String = myEncoder.encode(b);

        return randomBase64String;
    }


    /**
     * Verschluesselt den DocumentKey mit allen Public-Keys aus dem hasAccess Feld
     *
     * @param documentKey Schlüssel der den Vertrag verschlüsselt
     * @param hasAcc      JSONArray mit allen berechtigten Nutzern
     * @return BASE64 String
     * @throws Exception
     */
    public String encryptDocumentKey(String documentKey, JSONArray hasAcc) throws Exception {
        String geheim;
        JSONArray docKeys = new JSONArray();
        BASE64Encoder myEncoder = new BASE64Encoder();
        BASE64Decoder myDecoder = new BASE64Decoder();
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
        String docKeysString;
        docKeysString = myEncoder.encode(docKeys.toString().getBytes());

        return docKeysString;
    }

    /**
     * Entschluesselt einen BASE64 kodierten DocumentKey mittels dem user und dessen Private-Key
     *
     * @param documentKeyEnc BASE64 kodierter Text
     * @param user JSONObject eines Users
     * @return DocumentKey im Klartext
     * @throws Exception
     */
    public String decryptDocumentKey(String documentKeyEnc, JSONObject user) throws Exception {
        String username = user.get("name").toString();
        String encDocKeyUser = null;
        byte[] plainDocKey = null;
        byte[] cipherData = null;
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
            } else {
            }
        }

        return finalCiper;

    }

    /**
     * SecretKeySpecs erzeugt einen Key aus einem String
     * @param myKey String aus dem ein Key erzeugt werden soll
     * @return secretKey
     */
    public static SecretKeySpec setKey(String myKey) {
        MessageDigest sha = null;
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
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
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
    public static String encryptString(String strToEncrypt, String secret) {
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
    public static String decryptString(String strToDecrypt, String secret) {
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
        JSONArray hasAccess = new JSONArray();
        JSONArray data = new JSONArray();

        JSONObject peter = new JSONObject();
        JSONObject petKeyPair = generateKeyPair();
        peter.put("encryption" , petKeyPair);
        peter.put("name" , "Peter");

        JSONObject fred = new JSONObject();
        JSONObject freKeyPair = generateKeyPair();
        fred.put("encryption" , freKeyPair);
        fred.put("name" , "Federico");

        JSONObject secretStuff = new JSONObject();
        secretStuff.put("cash","10000€");
        secretStuff.put("time", 2);

        JSONObject secondSecretStuff = new JSONObject();
        secondSecretStuff.put("log","This is a long string with informations");
        secondSecretStuff.put("protocol","This is the protocol, im very happy");

        data.put(secretStuff);
        data.put(secondSecretStuff);

        //Bearbeiten der Berechtigungen
        hasAccess.put(peter);
        hasAccess.put(fred);

        String base64public = hasAccess.getJSONObject(0).getJSONObject("encryption").get("public").toString();
        byte[] publicBytes = Base64.getDecoder().decode(base64public);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        //Bibliothek Seehsam
        Seehsam sam = new Seehsam();

        //Encrypt Private-Key
        System.out.println("PrivateKey: " + peter.getJSONObject("encryption").get("private").toString());
        String encPriv = sam.encryptString(peter.getJSONObject("encryption").get("private").toString(),"password");
        System.out.println("EncPrivate: " + encPriv);
        System.out.println("DecPrivate: " + sam.decryptString(encPriv,"password"));


        //DocumentKey verschlüsseln
        String randomDoc = generateRandomDocumentKey();
        String encDocKey =  sam.encryptDocumentKey(randomDoc,hasAccess);

        System.out.println();
        System.out.println("Documentkey Klartext: ");
        System.out.println(randomDoc);
        System.out.println();
        System.out.println("Verschlüsselter Documentkey: ");
        System.out.println(encDocKey);
        System.out.println();


        //DocumentKey entschlüsseln Fred
        String decDocKeyFred = sam.decryptDocumentKey(encDocKey,fred);

        System.out.println();
        System.out.println("Entschlüsselter DocKeyFred: ");
        System.out.println(decDocKeyFred);


        //DocumentKey entschlüsseln Peter
        String decDocKeyPeter = sam.decryptDocumentKey(encDocKey,peter);

        System.out.println();
        System.out.println("Entschlüsselter DocKeyPeter: ");
        System.out.println(sam.decryptDocumentKey(encDocKey,peter));


        //Daten verschlüsseln Fred
        String dataCipherFred = sam.encryptString(data.toString(),decDocKeyFred);
        System.out.println();
        System.out.println("Verschlüsslte Daten Fred: ");
        System.out.println(dataCipherFred);

        //Daten entschlüsseln Fred
        String plainDataFred = sam.decryptString(dataCipherFred,decDocKeyFred);
        System.out.println();
        System.out.println("Entschlüsselte Daten Fred: ");
        System.out.println(plainDataFred);

    }
}