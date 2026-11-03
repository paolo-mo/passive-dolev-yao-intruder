import java.io.*;
import java.util.*;

public class ExtractCheck_hybrid {

    // Stream filenames depend on the capture; read the actual names from
    // handwritten_hybrid_rsa_aes_streams.json and adjust the map below.
    // The hybrid protocol has four steps: STEP_1 (s2c, PublicKey),
    // STEP_2 (c2s, byte[]), STEP_3 (s2c, byte[]), STEP_4 (s2c, byte[]).
    private static final Map<String, List<String>> CHANNELS = Map.of(
        "handwritten_hybrid_rsa_aes_STREAM_3_2.ser", List.of("STEP_2"),                      // c2s
        "handwritten_hybrid_rsa_aes_STREAM_3_1.ser", List.of("STEP_1", "STEP_3", "STEP_4")  // s2c
    );

    public static void main(String[] args) throws Exception {
        String prefix = args.length > 0 ? args[0] : "handwritten_hybrid_rsa_aes";

        for (Map.Entry<String, List<String>> e : CHANNELS.entrySet()) {
            String streamFile = e.getKey();
            List<String> steps = e.getValue();

            try (ObjectInputStream in =
                     new ObjectInputStream(new FileInputStream(streamFile))) {
                int i = 0;
                while (i < steps.size()) {
                    Object o;
                    try {
                        o = in.readObject();
                    } catch (EOFException eof) {
                        System.out.println(streamFile + ": EOF after "
                                + i + " object(s)");
                        break;
                    }
                    String stepFile = prefix + "_1_" + steps.get(i) + ".ser";
                    try (ObjectOutputStream out =
                             new ObjectOutputStream(new FileOutputStream(stepFile))) {
                        out.writeObject(o);
                    }
                    System.out.println(streamFile + " -> " + stepFile
                            + "  (" + friendlyName(o.getClass()) + ")");
                    i++;
                }
            }
        }
    }

    private static String friendlyName(Class<?> c) {
        if (c.isArray()) {
            return friendlyName(c.getComponentType()) + "[]";
        }
        return c.getName();
    }
}