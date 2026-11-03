import java.util.*;

public class Tutorial_06_ObjCheck_Map {

    public static Map<Tutorial_06_Steps, Tutorial_06_Channels> channelStepMap =
        new HashMap<>();

    static {
        channelStepMap.put(Tutorial_06_Steps.STEP_1,
            Tutorial_06_Channels.SERVER_to_CLIENT);
        channelStepMap.put(Tutorial_06_Steps.STEP_2,
            Tutorial_06_Channels.CLIENT_to_SERVER);
        channelStepMap.put(Tutorial_06_Steps.STEP_3,
            Tutorial_06_Channels.SERVER_to_CLIENT);
        channelStepMap.put(Tutorial_06_Steps.STEP_4,
            Tutorial_06_Channels.CLIENT_to_SERVER);
        channelStepMap.put(Tutorial_06_Steps.STEP_5,
            Tutorial_06_Channels.SERVER_to_CLIENT);
    }

    // Inverse: channel -> ordered list of steps expected on that channel.
    public static Map<Tutorial_06_Channels, List<Tutorial_06_Steps>>
            channelStepMapInverse() {
        Map<Tutorial_06_Channels, List<Tutorial_06_Steps>> inv =
            new HashMap<>();
        for (Tutorial_06_Channels c : Tutorial_06_Channels.values()) {
            inv.put(c, new ArrayList<>());
        }
        for (Tutorial_06_Steps s : Tutorial_06_Steps.values()) {
            inv.get(channelStepMap.get(s)).add(s);
        }
        return inv;
    }

    public static void main(String[] args) {
        Map<Tutorial_06_Channels, List<Tutorial_06_Steps>> inv =
            channelStepMapInverse();
        inv.forEach((c, steps) -> System.out.println(c + " -> " + steps));
    }
}