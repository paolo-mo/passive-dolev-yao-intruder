import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;

public class Server {
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.print("Введите сообщение: ");
        String message = sc.nextLine();


        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        try (ServerSocket serverSocket = new ServerSocket(6669)) {
            System.out.println("Сервер: Ожидание подключения клиента...");
            Socket clientSocket = serverSocket.accept();
            System.out.println("Сервер: Клиент подключен.");

            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            out.writeObject(publicKey);
			out.flush();
			
            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
            byte[] encryptedSymmetricKey = (byte[]) in.readObject();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            SecretKey symmetricKey = (SecretKey) cipher.unwrap(encryptedSymmetricKey, "AES", Cipher.SECRET_KEY);


            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            byte[] encryptedMessage = aesCipher.doFinal(message.getBytes());

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] digitalSignature = signature.sign();

            out.writeObject(encryptedMessage);
			out.flush();
            out.writeObject(digitalSignature);
			out.flush();
            System.out.println("Сервер: Зашифрованное сообщение и подпись отправлены клиенту.");
        }
    }
}
