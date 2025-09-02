public class PacketPart {
    public String type; // "header", "cookie", "query", "body"
    public String name; // Name of the part (e.g., "User-Agent", "sessionid", "(body)")
    public String value; // For textual parts (headers, cookies, query)
    public byte[] rawBytes; // For binary body content
    public boolean essential; // Marked true if required for response fidelity

    // Constructor for textual parts
    public PacketPart(String type, String name, String value) {
        this.type = type;
        this.name = name;
        this.value = value;
        this.essential = true;
    }

    // Constructor for binary body parts
    public PacketPart(String type, String name, byte[] rawBytes) {
        this.type = type;
        this.name = name;
        this.rawBytes = rawBytes;
        this.essential = true;
    }

    // Utility: get body content as string (if needed for logging)
    public String getBodyAsString() {
        return rawBytes != null ? new String(rawBytes) : value;
    }

    @Override
    public String toString() {
        if ("body".equals(type)) {
            return "[body] " + name + " (" + (rawBytes != null ? rawBytes.length + " bytes" : "empty") + ")";
        }
        return "[" + type + "] " + name + " = " + value + " | essential: " + essential;
    }
}
