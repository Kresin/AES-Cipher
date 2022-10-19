package runner;

import cipher.AESCipher;
import cipher.RSACipher;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        RSACipher rsaCipher = new RSACipher();
        rsaCipher.generateAndSaveKeyPair();

        AESCipher aesCipher = new AESCipher();
        IvParameterSpec ivParameterSpec = aesCipher.generateAndSaveInitializationVector();
        SecretKey secretKey = aesCipher.generateAndSaveKey();

        System.out.println("Informe o caminho do arquivo a ser criptografado:");
        Scanner scanner = new Scanner(System.in);
        String pathInput = scanner.nextLine();

        System.out.println("Informe o caminho de destino do arquivo criptografado:");
        scanner = new Scanner(System.in);
        String pathOutput = scanner.nextLine();

        aesCipher.encryptFile(secretKey, ivParameterSpec, pathInput, pathOutput);

        System.out.println("Informe o caminho de destino do arquivo a ser descriptografado:");
        scanner = new Scanner(System.in);
        String pathDecryptOutput = scanner.nextLine();
        aesCipher.decryptFile(pathOutput, pathDecryptOutput);
    }

}
