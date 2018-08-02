import org.json.JSONArray;
import org.json.JSONObject;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class hybridEncryption {

    private static int RSA_KEY_SIZE = 4096;
    private static int AES_KEY_SIZE = 256;
    private static int IV_KEY_SIZE = 16;
    private static int HASH_KEY_SIZE = 16;

    /**
     * Generiert ein RSA Schlüsselpaar mit einem Public-Key und Private-Key
     * Der Private-Key wird mit der Passphrase verschlüsselt
     * Schlüssellänge: 4096 (RSA_KEY_SIZE)
     *
     * @param passphrase Kennwort des Nutzers
     * @return JSONObject with public and private key
     */
    private  JSONObject generateKeyPair(String passphrase) throws Exception {
        KeyPair keyPair;
        KeyPairGenerator keygenerator;
        JSONObject JSONkeyPairObject = new JSONObject();
        byte[] privateKeyBytes;
        byte[] publicKeyBytes;
        String publicKey;
        String privateKey;

        keygenerator = KeyPairGenerator.getInstance("RSA");
        keygenerator.initialize(RSA_KEY_SIZE);
        keyPair = keygenerator.genKeyPair();

        privateKeyBytes = keyPair.getPrivate().getEncoded();
        privateKey = Base64.getEncoder().encodeToString(privateKeyBytes);
        JSONkeyPairObject.put("private", encryptString(privateKey, passphrase));

        publicKeyBytes = keyPair.getPublic().getEncoded();
        publicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
        JSONkeyPairObject.put("public", publicKey);

        return JSONkeyPairObject;
    }

    /**
     * Generiert einen zufälligen Documentkey
     * Länge: AES_KEY_SIZE
     *
     * @return Zufälliger DocumentKey als Base64 String
     */
    private  String generateRandomDocumentKey() throws NoSuchAlgorithmException {
        int keyBitSize = AES_KEY_SIZE;
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        Key secretKey = keyGenerator.generateKey();
        byte[] keyBytes = secretKey.getEncoded();
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(keyBitSize, secureRandom);
        BASE64Encoder myEncoder = new BASE64Encoder();
        return myEncoder.encode(keyBytes);
    }

    /**
     * Verschluesselt den DocumentKey mit allen Public-Keys aus dem hasAccess Feld
     *
     * @param documentKey Schlüssel der den Vertrag verschlüsselt
     * @param hasAccess   JSONArray mit allen berechtigten Nutzern
     * @return BASE64 String
     */
    private String encryptDocumentKey(String documentKey, JSONArray hasAccess) throws Exception {
        JSONArray documentKeys = new JSONArray();
        JSONObject encryption = new JSONObject();

        BASE64Encoder myEncoder = new BASE64Encoder();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec;
        PublicKey publicKey;
        byte[] publicKeyBytes;
        byte[] cipherTextBytes;
        String publicKeyString;
        String cipherText;

        for (int i = 0; i < hasAccess.length(); i++) {
            Cipher cipher = Cipher.getInstance("RSA");
            publicKeyString = hasAccess.getJSONObject(i).getJSONObject("encryption").get("public").toString();
            publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            publicKey = keyFactory.generatePublic(publicKeySpec);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            cipherTextBytes = cipher.doFinal(documentKey.getBytes());
            cipherText = myEncoder.encode(cipherTextBytes);
            encryption.put(hasAccess.getJSONObject(i).get("name").toString(), cipherText);
            documentKeys.put(encryption);
        }
        return myEncoder.encode(documentKeys.toString().getBytes());
    }

    /**
     * Entschluesselt einen BASE64 kodierten DocumentKey mittels dem user und dessen Private-Key
     * Der Private-Key wird mit der passphrase entschlüsselt
     *
     * @param encryptedDocumentKey BASE64 kodierter Text
     * @param user           JSONObject eines Users
     * @return DocumentKey im Klartext
     */
    private String decryptDocumentKey(String encryptedDocumentKey, JSONObject user, String key) throws Exception {
        String username = user.get("name").toString();
        String plainText = null;
        String documentKeyString;
        String privateKeyString;
        BASE64Decoder myDecoder = new BASE64Decoder();
        Cipher cipher;
        KeyFactory keyFactory;
        RSAPrivateKey privateKey;
        byte[] documentKey;
        byte[] cipherBytes;
        byte[] privateKeyBytes;
        JSONArray jsa = new JSONArray(new String(myDecoder.decodeBuffer(encryptedDocumentKey)));

        for (int i = 0; i < jsa.length(); i++) { //Search for name!
            if (jsa.getJSONObject(i).has(username)) {
                documentKeyString = jsa.getJSONObject(i).get(username).toString();
                documentKey = myDecoder.decodeBuffer(documentKeyString);
                cipher = Cipher.getInstance("RSA");
                privateKeyString = decryptString(user.getJSONObject("encryption").get("private").toString(), key);
                privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
                PKCS8EncodedKeySpec specs = new PKCS8EncodedKeySpec(privateKeyBytes);
                keyFactory = KeyFactory.getInstance("RSA");
                privateKey = (RSAPrivateKey) keyFactory.generatePrivate(specs);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                cipherBytes = cipher.doFinal(documentKey);
                plainText = new String(cipherBytes);
            }
        }
        return plainText;
    }


    /**
     * Verschlüsselt einen String mittels AES-CBC-PKCS5Padding
     *
     * @param plainText String der verschlüsselt werden soll
     * @param key       passphrase zum verschlüsseln
     * @return String Cipher-Text
     */
    private  String encryptString(String plainText, String key) throws Exception {
        byte[] clean = plainText.getBytes();
        byte[] iv = new byte[IV_KEY_SIZE];
        byte[] keyBytes = new byte[HASH_KEY_SIZE];
        byte[] encryptedIVAndText;
        byte[] encrypted;
        String cipherText;

        SecureRandom random = new SecureRandom();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        random.nextBytes(iv);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key.getBytes("UTF-8"));
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        encrypted = cipher.doFinal(clean);
        encryptedIVAndText = new byte[IV_KEY_SIZE + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, IV_KEY_SIZE);
        System.arraycopy(encrypted, 0, encryptedIVAndText, IV_KEY_SIZE, encrypted.length);
        cipherText = Base64.getEncoder().encodeToString(encryptedIVAndText);

        return cipherText;
    }


    /**
     * Entschlüsselt einen String mittels AES-CBC-PKCS5Padding
     *
     * @param cipherText String der entschlüsselt werden soll
     * @param key        passphrase zum entschlüsseln
     * @return
     */
    private  String decryptString(String cipherText, String key) throws Exception {
        byte[] encryptedIvTextBytes = Base64.getDecoder().decode(cipherText);
        byte[] iv = new byte[IV_KEY_SIZE];
        byte[] encryptedBytes;
        byte[] keyBytes = new byte[HASH_KEY_SIZE];
        ;
        byte[] decrypted;
        int encryptedSize;
        String plainText;

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
        encryptedSize = encryptedIvTextBytes.length - IV_KEY_SIZE;
        encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, IV_KEY_SIZE, encryptedBytes, 0, encryptedSize);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(key.getBytes());
        System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        decrypted = cipherDecrypt.doFinal(encryptedBytes);
        plainText = new String(decrypted);

        return plainText;
    }


    public static void main(String[] args) {
    }
}