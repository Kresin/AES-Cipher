package file;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class FileService {

    public void saveKey(String path, String key) {
        BufferedWriter bufferedWriter = getBufferedWriter(path);
        try {
            bufferedWriter.write(key);
        } catch (IOException ex) {
            System.out.println("Erro ao escrever no arquivo");
        } finally {
            try {
                bufferedWriter.close();
            } catch (IOException ex) {
                System.out.println("Erro ao fechar arquivo após a escrita");
            }
        }
    }

    private BufferedWriter getBufferedWriter(String filePath) {
        File file = new File(filePath);
        FileWriter fileWriter = null;
        try {
            fileWriter = new FileWriter(file);
        } catch (IOException e) {
            System.out.println("Erro ao carregar o arquivo para escrita");
        }
        return new BufferedWriter(fileWriter);
    }

    public String getFileContent(String path) {
        BufferedReader bufferedReader = getBufferedReader(path);
        String fileContent = "";
        try {
            fileContent = bufferedReader.readLine();
        } catch (IOException e) {
            System.out.println("Erro ao ler o arquivo");
        } finally {
            try {
                bufferedReader.close();
            } catch (IOException e) {
                System.out.println("Erro ao fechar o arquivo");
            }
        }
        return fileContent;
    }

    private BufferedReader getBufferedReader(String filePath) {
        File file = new File(filePath);
        FileReader fileReader = null;
        try {
            fileReader = new FileReader(file);
        } catch (FileNotFoundException e) {
            System.out.println("Arquivo não encontrado");
        }
        return new BufferedReader(fileReader);
    }

}
