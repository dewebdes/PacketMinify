import burp.*;

import java.util.*;
import java.net.URL;

public class PacketExtractor {
    private IExtensionHelpers helpers;
    private IRequestInfo requestInfo;
    private byte[] requestBytes;

    public PacketExtractor(IExtensionHelpers helpers, IRequestInfo requestInfo, byte[] requestBytes) {
        this.helpers = helpers;
        this.requestInfo = requestInfo;
        this.requestBytes = requestBytes;
    }

    public List<PacketPart> extractParts() {
        List<PacketPart> parts = new ArrayList<>();

        // Query Parameters
        URL url = requestInfo.getUrl();
        String query = url.getQuery();
        if (query != null) {
            for (String param : query.split("&")) {
                String[] kv = param.split("=", 2);
                String name = kv[0];
                String value = kv.length > 1 ? kv[1] : "";
                parts.add(new PacketPart("query", name, value));
            }
        }

        // Headers
        List<String> headers = requestInfo.getHeaders();
        for (int i = 1; i < headers.size(); i++) { // skip request line
            String line = headers.get(i);
            int idx = line.indexOf(":");
            if (idx > 0) {
                String name = line.substring(0, idx).trim();
                String value = line.substring(idx + 1).trim();
                if (name.equalsIgnoreCase("Cookie")) {
                    // Split cookies
                    for (String cookie : value.split(";")) {
                        String[] kv = cookie.split("=", 2);
                        String cname = kv[0].trim();
                        String cvalue = kv.length > 1 ? kv[1].trim() : "";
                        parts.add(new PacketPart("cookie", cname, cvalue));
                    }
                } else {
                    parts.add(new PacketPart("header", name, value));
                }
            }
        }

        // Body
        int bodyOffset = requestInfo.getBodyOffset();
        String body = new String(Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length));
        if (!body.trim().isEmpty()) {
            parts.add(new PacketPart("body", "(body)", body));
        }

        return parts;
    }
}
