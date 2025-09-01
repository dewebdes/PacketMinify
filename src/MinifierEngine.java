package burp;

import java.util.List;
import java.util.ArrayList;

public class MinifierEngine {
    public static List<byte[]> generateVariants(byte[] original, IExtensionHelpers helpers) {
        List<byte[]> variants = new ArrayList<>();
        variants.add(original); // Variant 1: original
        // Add more symbolic variants here (e.g. stripped headers, altered cookies)
        return variants;
    }
}
