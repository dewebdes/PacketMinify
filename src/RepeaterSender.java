import burp.*;

import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class RepeaterSender {
    public static void sendToRepeater(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
            String minimizedRequest, String host) {
        try {
            // Parse minimized request into headers and body
            String[] split = minimizedRequest.split("\r\n\r\n", 2);
            String headerBlock = split[0];
            String body = split.length > 1 ? split[1] : "";

            String[] lines = headerBlock.split("\r\n");
            Map<String, String> headerMap = new LinkedHashMap<>();
            String requestLine = lines[0]; // Preserve the first line

            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                int colonIndex = line.indexOf(":");
                if (colonIndex == -1)
                    continue;

                String name = line.substring(0, colonIndex).trim().toLowerCase();
                String value = line.substring(colonIndex + 1).trim();

                // Only keep the first occurrence of each header name
                if (!headerMap.containsKey(name)) {
                    headerMap.put(name, value);
                }
            }

            // Rebuild headers list
            List<String> headers = new ArrayList<>();
            headers.add(requestLine); // Add request line first
            for (Map.Entry<String, String> entry : headerMap.entrySet()) {
                headers.add(capitalize(entry.getKey()) + ": " + entry.getValue());
            }

            byte[] requestBytes = helpers.buildHttpMessage(headers, body.getBytes());

            // Extract host and port
            boolean isHttps = true;
            int port = 443;
            if (host.contains(":")) {
                String[] hp = host.split(":");
                host = hp[0];
                port = Integer.parseInt(hp[1]);
            }

            IHttpService service = helpers.buildHttpService(host, port, isHttps);
            callbacks.sendToRepeater(host, port, isHttps, requestBytes, null);
            callbacks.printOutput("Minimized packet sent to Repeater.");
        } catch (Exception e) {
            callbacks.printError("Failed to send to Repeater: " + e.getMessage());
        }
    }

    private static String capitalize(String input) {
        if (input == null || input.isEmpty())
            return input;
        return input.substring(0, 1).toUpperCase() + input.substring(1);
    }

}
