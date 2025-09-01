import burp.*;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class RepeaterSender {
    public static void sendToRepeater(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
            String minimizedRequest, String host) {
        try {
            // Parse minimized request into headers and body
            String[] split = minimizedRequest.split("\r\n\r\n", 2);
            String headerBlock = split[0];
            String body = split.length > 1 ? split[1] : "";

            String[] lines = headerBlock.split("\r\n");
            List<String> headers = new ArrayList<>();
            for (String line : lines) {
                headers.add(line);
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
}
