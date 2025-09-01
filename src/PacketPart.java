public class PacketPart {
    public String type; // "header", "cookie", "query", "body"
    public String name;
    public String value;
    public boolean essential;

    public PacketPart(String type, String name, String value) {
        this.type = type;
        this.name = name;
        this.value = value;
        this.essential = true; // default to true, will be tested later
    }
}
