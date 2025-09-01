import burp.*;

import java.util.*;
import java.net.URL;

public class PacketMinifier {
    public static String buildMinimizedRequest(IRequestInfo requestInfo, List<PacketPart> parts) {
        List<String> headers = new ArrayList<>();
        String method = requestInfo.getMethod();
        URL url = requestInfo.getUrl();
        String path = url.getPath();
        String query = "";

        // Rebuild query string
        List<String> queryParams = new ArrayList<>();
        for (PacketPart part : parts) {
            if (part.essential && part.type.equals("query")) {
                queryParams.add(part.name + "=" + part.value);
            }
        }
        if (!queryParams.isEmpty()) {
            query = "?" + String.join("&", queryParams);
        }

        // Start with request line
        String requestLine = method + " " + path + query + " HTTP/1.1";
        headers.add(requestLine);

        // Host header
        headers.add("Host: " + url.getHost());

        // Rebuild headers
        Map<String, String> headerMap = new LinkedHashMap<>();
        for (PacketPart part : parts) {
            if (part.essential && part.type.equals("header")) {
                headerMap.put(part.name, part.value);
            }
        }

        // Rebuild cookies
        List<String> cookieList = new ArrayList<>();
        for (PacketPart part : parts) {
            if (part.essential && part.type.equals("cookie")) {
                cookieList.add(part.name + "=" + part.value);
            }
        }
        if (!cookieList.isEmpty()) {
            headerMap.put("Cookie", String.join("; ", cookieList));
        }

        for (Map.Entry<String, String> entry : headerMap.entrySet()) {
            headers.add(entry.getKey() + ": " + entry.getValue());
        }

        // Rebuild body
        String body = "";
        for (PacketPart part : parts) {
            if (part.essential && part.type.equals("body")) {
                body = part.value;
                break;
            }
        }

        return String.join("\r\n", headers) + "\r\n\r\n" + body;
    }
}
