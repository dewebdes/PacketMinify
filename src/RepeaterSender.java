import burp.*;

public class RepeaterSender {
    public static void sendToRepeater(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
            byte[] minimizedRequest, String host) {
        try {
            // Extract host and port
            boolean isHttps = true;
            int port = 443;
            if (host.contains(":")) {
                String[] hp = host.split(":");
                host = hp[0];
                port = Integer.parseInt(hp[1]);
            }

            IHttpService service = helpers.buildHttpService(host, port, isHttps);
            callbacks.sendToRepeater(host, port, isHttps, minimizedRequest, null);
            callbacks.printOutput("Minimized packet sent to Repeater.");
        } catch (Exception e) {
            callbacks.printError("Failed to send to Repeater: " + e.getMessage());
        }
    }
}
