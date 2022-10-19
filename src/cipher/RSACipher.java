package cipher;

import file.FileService;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSACipher {

    private static final String PRIVATE_KEY_LOCATION = "./temp/PrivateKey.txt";
    private static final String PUBLIC_KEY_LOCATION = "./temp/PublicKey.txt";

    public String encrypt(byte[] keyToEncode) {
        Cipher cipher;
        FileService fileService = new FileService();
        try {
            String fileContent = fileService.getFileContent(PUBLIC_KEY_LOCATION);
            byte[] rsaPublicKeyBytes = Hex.decodeHex(fileContent);
            X509EncodedKeySpec keyEncoded = new X509EncodedKeySpec(rsaPublicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keyEncoded);

            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Hex.encodeHexString(cipher.doFinal(keyToEncode));
        } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 NoSuchPaddingException | DecoderException | InvalidKeySpecException e) {
            throw new RuntimeException("Erro ao criptografar a chave: ", e);
        }
    }

    public byte[] decrypt(byte[] keyToDecrypt) {
        Cipher cipher;
        FileService fileService = new FileService();
        try {
            String fileContent = fileService.getFileContent(PRIVATE_KEY_LOCATION);
            byte[] rsaPrivateKeyBytes = Hex.decodeHex(fileContent);
            PKCS8EncodedKeySpec keyEncoded = new PKCS8EncodedKeySpec(rsaPrivateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keyEncoded);

            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(keyToDecrypt);
        } catch (NoSuchAlgorithmException | DecoderException | InvalidKeySpecException | InvalidKeyException |
                 BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            throw new RuntimeException("Erro ao descriptografar a chave: ", e);
        }
    }

    public void generateAndSaveKeyPair() {
        FileService fileService = new FileService();
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Erro ao gerar a KeyPairGenerator: ", e);
        }
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        KeyFactory keyFactory;
        RSAPublicKeySpec publicKeySpec;
        RSAPrivateKeySpec privateKeySpec;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
            privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        System.out.println("Módulo (Chave pública): " + publicKeySpec.getModulus());
        System.out.println("Expoente(Chave pública): " + publicKeySpec.getPublicExponent());
        fileService.saveKey(PUBLIC_KEY_LOCATION, Hex.encodeHexString(keyPair.getPublic().getEncoded()));

        System.out.println("Módulo (Chave privada): " + privateKeySpec.getModulus());
        System.out.println("Expoente (Chave privada): " + privateKeySpec.getPrivateExponent());
        fileService.saveKey(PRIVATE_KEY_LOCATION, Hex.encodeHexString(keyPair.getPrivate().getEncoded()));
    }

}
