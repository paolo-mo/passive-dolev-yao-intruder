import java.io.*;
import java.util.*;

public class ExtractCheck_07 {

    // Stream filenames depend on the capture; adjust to match dir output.
    // For the localhost capture the two files are the two directions of
    // the single TCP connection on port 6670.
	private static final Map<String, List<String>> CHANNELS = Map.of(
		"Tutorial_07_STREAM_1_1.ser", List.of("STEP_1", "STEP_3", "STEP_5"), // s2c
		"Tutorial_07_STREAM_1_2.ser", List.of("STEP_2", "STEP_4")            // c2s
	);

    public static void main(String[] args) throws Exception {
        String prefix = args.length > 0 ? args[0] : "Tutorial_07";

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
                            + "  (" + o.getClass().getName() + ")");
                    i++;
                }
            }
        }
    }
}