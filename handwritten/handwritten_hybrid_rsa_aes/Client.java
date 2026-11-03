import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.PublicKey;
import java.security.Signature;

public class Client {
    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket("localhost", 6669)) {
            System.out.println("Клиент: Подключение к серверу установлено.");

            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            PublicKey publicKey = (PublicKey) in.readObject();

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey symmetricKey = keyGen.generateKey();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.WRAP_MODE, publicKey);
            byte[] encryptedSymmetricKey = cipher.wrap(symmetricKey);

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.writeObject(encryptedSymmetricKey);
			out.flush();
			
            byte[] encryptedMessage = (byte[]) in.readObject();
            byte[] digitalSignature = (byte[]) in.readObject();

            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            byte[] decryptedMessage = aesCipher.doFinal(encryptedMessage);
            String message = new String(decryptedMessage);
            System.out.println("Клиент: Расшифрованное сообщение: " + message);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(message.getBytes());
            boolean isSignatureValid = signature.verify(digitalSignature);
            if (isSignatureValid) {
                System.out.println("Клиент: Электронная подпись действительна.");
            } else {
                System.out.println("Клиент: Электронная подпись недействительна!");
            }
        }
    }
}
