import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Tutorial_07 {

    static final byte[] SHARED_AES_KEY = new byte[32];
    static {
        Arrays.fill(SHARED_AES_KEY, (byte) 0x42);
    }

    static KeyPair RSA_KEYPAIR;

    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        RSA_KEYPAIR = kpg.generateKeyPair();

        if (args.length != 1) { usage(); return; }
        if (args[0].equalsIgnoreCase("server"))      new server_07();
        else if (args[0].equalsIgnoreCase("client")) new client_07();
        else usage();
    }

    static void usage() {
        System.out.println("USAGE: java Tutorial_07 [client|server]");
    }
}

class server_07 {
    public server_07() throws Exception {
        ServerSocket ss = new ServerSocket(6671);
        System.out.println("Server listening on 6671");
        Socket s = ss.accept();

        ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
        out.flush();
        ObjectInputStream in = new ObjectInputStream(s.getInputStream());

        // STEP 1: S -> C (plain String)
        out.writeObject("Hello! What's your name?");
        out.flush();

        // STEP 2: C -> S (plain String)
        String name = (String) in.readObject();
        System.out.println("Received name: " + name);

        // STEP 3: S -> C (SealedObject wrapping a String)
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE,
                 new SecretKeySpec(Tutorial_07.SHARED_AES_KEY, "AES"),
                 new GCMParameterSpec(128, iv));

        SealedObject sealed = new SealedObject(
                "Hi " + name + "! Here is a sealed message", enc);
        out.writeObject(sealed);
        out.flush();

        // STEP 4: C -> S (SignedObject wrapping a String)
        SignedObject signed = (SignedObject) in.readObject();
        System.out.println("Received signed object, payload class: "
                + signed.getObject().getClass().getName());
        System.out.println("  signature algorithm: " + signed.getAlgorithm());

        // STEP 5: S -> C (plain String)
        out.writeObject("Thank you " + name + ", received your signed object");
        out.flush();

        out.close(); in.close(); s.close(); ss.close();
        System.out.println("Server done.");
    }
}

class client_07 {
    public client_07() throws Exception {
        Socket s = new Socket("127.0.0.1", 6671);

        ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
        out.flush();
        ObjectInputStream in = new ObjectInputStream(s.getInputStream());

        // STEP 1
        String msg = (String) in.readObject();
        System.out.println("S->C: " + msg);

        // STEP 2
        out.writeObject("alice");
        out.flush();

        // STEP 3 — decryption retrieves IV from the sealed object
        SealedObject sealed = (SealedObject) in.readObject();
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
        String opened = (String) sealed.getObject(
                new SecretKeySpec(Tutorial_07.SHARED_AES_KEY, "AES"));
        System.out.println("S->C (sealed): " + opened);

        // STEP 4
        SignedObject signed = new SignedObject(
                "hello from alice",
                Tutorial_07.RSA_KEYPAIR.getPrivate(),
                Signature.getInstance("SHA256withRSA"));
        out.writeObject(signed);
        out.flush();

        // STEP 5
        msg = (String) in.readObject();
        System.out.println("S->C: " + msg);

        out.close(); in.close(); s.close();
        System.out.println("Client done.");
    }
}