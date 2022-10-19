package cipher;

import file.FileService;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESCipher {

    private static final String AES_KEY = "./temp/AESKey.txt";
    private static final String IV_VECTOR = "./temp/InitializationVector.txt";

    public void encryptFile(SecretKey key, IvParameterSpec ivParameterSpec, String inputFilePath, String outputFilePath) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
             FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath)) {
            processFile(cipher, fileInputStream, fileOutputStream);
        } catch (IllegalBlockSizeException | IOException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private void processFile(Cipher cipher, InputStream inputStream, OutputStream outputStream) throws IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = inputStream.read(ibuf)) != -1) {
            byte[] obuf = cipher.update(ibuf, 0, len);
            if (obuf != null) {
                outputStream.write(obuf);
            }
        }
        byte[] obuf = cipher.doFinal();
        if (obuf != null) {
            outputStream.write(obuf);
        }
    }

    public SecretKey generateAndSaveKey() {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Erro ao criar o KeyGenerator", e);
        }
        keyGenerator.init(128);

        SecretKey aesKey = keyGenerator.generateKey();
        RSACipher cipher = new RSACipher();
        String aesKeyEncrypted = cipher.encrypt(aesKey.getEncoded());

        System.out.println("Chave AES gerada: " + Hex.encodeHexString(aesKey.getEncoded()));
        System.out.println("Chave AES cifrada: " + aesKeyEncrypted);

        FileService fileService = new FileService();
        fileService.saveKey(AES_KEY, aesKeyEncrypted);

        return aesKey;
    }

    public IvParameterSpec generateAndSaveInitializationVector() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[128 / 8];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        FileService fileService = new FileService();
        fileService.saveKey(IV_VECTOR, Hex.encodeHexString(iv));

        return ivParameterSpec;
    }

    public void decryptFile(String inputFilePath, String outputFilePath) {
        try {
            FileService fileService = new FileService();
            String aesKeyHexString = fileService.getFileContent(AES_KEY);
            byte[] aesEncryptedKeyBytes = Hex.decodeHex(aesKeyHexString);

            RSACipher rsaCipher = new RSACipher();
            byte[] aesDecryptedKeyBytes = rsaCipher.decrypt(aesEncryptedKeyBytes);

            SecretKeySpec secretKeySpec = new SecretKeySpec(aesDecryptedKeyBytes, "AES");

            String ivHexString = fileService.getFileContent(IV_VECTOR);
            byte[] iv = Hex.decodeHex(ivHexString);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ci.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
                 FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath)) {
                processFile(ci, fileInputStream, fileOutputStream);
            }
        } catch (DecoderException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 IOException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

}
