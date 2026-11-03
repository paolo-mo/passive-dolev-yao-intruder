import anbxj.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Scanner;

public class Tutorial_06 {

    private static String host_server = "127.0.0.1";
    private static int port = 6669;
    private static String usage = "USAGE: java Tutorial_06 [client|server]";
    private static String configFileName = "Tutorial_06.properties";
    private static String keystorepath = null;
    private static Crypto_Config crypto_config = null;

    public static void main(String[] args) {

        Channel_Properties cp;
        Channel_Settings cs;
        Crypto_KeyStoreSettings_Map kss;
        AnB_Crypto_Wrapper anb;

        Properties configFile = new Properties();
        InputStream propertiesStream = Tutorial_06.class.getResourceAsStream(configFileName);
        if (propertiesStream == null) {
            System.out.println("Config file not found: " + configFileName);
            System.exit(0);
        }
        try {
            configFile.load(propertiesStream);
            crypto_config = new Crypto_Config(configFile);
        } catch (IOException e) {
            System.out.println("Error reading config file: " + configFileName);
            e.printStackTrace();
            System.exit(1);
        }
        keystorepath = configFile.getProperty("keypath");

        if (args.length != 1) {
            System.out.println(usage);
            return;
        }

        AnBx_Debug.setAppname(Tutorial_06.class + "-" + args[0]);
        AnBx_Debug.setALL(true);

        if (args[0].equalsIgnoreCase("client")) {
            kss = new Crypto_KeyStoreSettings_Map(keystorepath, "alice");
            cs = new Channel_Settings(Channel_Roles.CLIENT, host_server, port);
            anb = new AnB_Crypto_Wrapper(kss, crypto_config);
            cp = new Channel_Properties(cs);
            new client_06(anb, cp);
        } else if (args[0].equalsIgnoreCase("server")) {
            kss = new Crypto_KeyStoreSettings_Map(keystorepath, "bob");
            cs = new Channel_Settings(Channel_Roles.SERVER, host_server, port);
            anb = new AnB_Crypto_Wrapper(kss, crypto_config);
            cp = new Channel_Properties(cs);
            new server_06(anb, cp);
        } else {
            System.out.println(usage);
        }
    }
}

class client_06 {

    public client_06(AnB_Crypto_Wrapper anb, Channel_Properties cp) {
        super();

        Crypto_SignedObject signedmsg;
        Scanner scanner = new Scanner(System.in);
        Channel_Abstraction c = Channel.setup(cp);

        c.Open();

        // STEP 1: server -> client (String)
        String msg = (String) c.Receive();
        System.out.println("S->C: " + msg);

        // STEP 2: client -> server (String, the name)
        msg = scanner.nextLine();
        c.Send(msg);

        // STEP 3: server -> client (String, the challenge)
        msg = (String) c.Receive();
        System.out.println("S->C: " + msg);

        // STEP 4: client -> server (Crypto_SignedObject)
        msg = scanner.nextLine();
        signedmsg = anb.sign(msg);
        c.Send(signedmsg);

        // STEP 5: server -> client (String, verification result)
        msg = (String) c.Receive();
        System.out.println("S->C: " + msg);

        c.Close();
        scanner.close();

        System.out.println("[ROLE_A-ALWAYS] - All sessions completed: 1/1 - Sequential");
    }
}

class server_06 {

    public server_06(AnB_Crypto_Wrapper anb, Channel_Properties cp) {
        super();

        String name;
        Channel_Abstraction s = Channel.setup(cp);

        do {
            s.Open();

            // STEP 1: server -> client (String)
            String msg = "Hello! What's your name?";
            s.Send(msg);

            // STEP 2: client -> server (String, the name)
            name = (String) s.Receive();

            // STEP 3: server -> client (String, the challenge)
            s.Send("Hi " + name + "! Please sign this message:\n"
                    + anb.getName() + "," + anb.getTimeStamp() + "\n"
                    + "Cut&Paste and press <ENTER>");

            // STEP 4: client -> server (Crypto_SignedObject)
            msg = (String) anb.verify((Crypto_SignedObject) s.Receive(), name);

            // STEP 5: server -> client (String, verification result)
            if (msg == null) {
                s.Send("I am sorry " + name + ", I am unable to verify your signature");
            } else {
                s.Send("Thank you " + name + ", your signature has been verified\n"
                        + "Your message was: " + msg);
            }

            System.out.println("C->S verified message: " + msg);
            s.Close();
        } while (true);
    }
}