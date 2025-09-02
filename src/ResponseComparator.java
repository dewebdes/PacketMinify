import burp.*;
import java.security.MessageDigest;
import java.util.Arrays;

public class ResponseComparator {

    // 🔍 Main comparison method
    public static boolean isEssentialChange(byte[] originalResponse, byte[] currentResponse,
            int originalStatus, int currentStatus) {
        // ⚡ Status code mismatch
        if (originalStatus != currentStatus) {
            return true;
        }

        // 📏 Adaptive content-length delta
        int originalLength = originalResponse.length;
        int currentLength = currentResponse.length;
        int delta = Math.abs(currentLength - originalLength);
        int threshold = Math.max(50, originalLength / 20); // 5% threshold

        if (delta > threshold) {
            return true;
        }

        // 🧪 Optional hash comparison (disabled by default)
        // if (!Arrays.equals(hash(originalResponse), hash(currentResponse))) {
        // return true;
        // }

        // 🧙 Optional symbolic marker scan (e.g., "Access Denied", "Invalid Token")
        // String bodyText = new String(currentResponse);
        // if (bodyText.contains("Access Denied") || bodyText.contains("Invalid Token"))
        // {
        // return true;
        // }

        return false;
    }

    // 🔐 SHA-256 hash helper
    private static byte[] hash(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            return new byte[0];
        }
    }
}
