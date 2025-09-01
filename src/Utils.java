public class Utils {
    public static boolean isNullOrEmpty(String val) {
        return val == null || val.trim().isEmpty();
    }

    public static String safeSplit(String input, String delimiter, int index) {
        String[] parts = input.split(delimiter, index + 1);
        return parts.length > index ? parts[index].trim() : "";
    }

    public static String stripPrefix(String input, String prefix) {
        return input.startsWith(prefix) ? input.substring(prefix.length()).trim() : input.trim();
    }

    public static void log(String label, String value) {
        System.out.println("[PacketMinify] " + label + ": " + value);
    }
}
