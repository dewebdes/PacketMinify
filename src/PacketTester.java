import burp.*;

import java.util.*;

public class PacketTester {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse originalMessage;
    private List<PacketPart> parts;
    private byte[] originalRequest;
    private int originalStatus;
    private int originalLength;

    public PacketTester(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
            IHttpRequestResponse originalMessage, List<PacketPart> parts) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.originalMessage = originalMessage;
        this.parts = parts;
        this.originalRequest = originalMessage.getRequest();

        IHttpService service = originalMessage.getHttpService();
        byte[] response = callbacks.makeHttpRequest(service, originalRequest).getResponse();
        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        this.originalStatus = responseInfo.getStatusCode();
        this.originalLength = response.length;
    }

    public List<PacketPart> identifyEssentialParts() {
        for (PacketPart part : parts) {

            part.essential = false;

            byte[] modifiedRequest = buildModifiedRequest(part);
            IHttpService service = originalMessage.getHttpService();
            byte[] response = callbacks.makeHttpRequest(service, modifiedRequest).getResponse();

            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            int status = responseInfo.getStatusCode();
            int length = response.length;

            if (status != originalStatus || length != originalLength) {
                part.essential = true;
            }

            callbacks.printOutput(String.format("Tested %s: %s = %s | essential: %s",
                    part.type, part.name, part.value, part.essential));

            try {
                Thread.sleep(3000); // ⏱️ 3-second pacing
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                callbacks.printError("Thread interrupted during delay: " + e.getMessage());
                break;
            }
        }

        return parts;
    }

    private byte[] buildModifiedRequest(PacketPart excludedPart) {
        IRequestInfo requestInfo = helpers.analyzeRequest(originalMessage);
        List<String> rawHeaders = requestInfo.getHeaders();
        int bodyOffset = requestInfo.getBodyOffset();
        String body = new String(Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length));

        // 🧼 Deduplicate headers
        Map<String, String> distinctHeaderMap = new LinkedHashMap<>();
        String requestLine = rawHeaders.get(0);
        distinctHeaderMap.put("request-line", requestLine);

        for (int i = 1; i < rawHeaders.size(); i++) {
            String header = rawHeaders.get(i);
            int colonIndex = header.indexOf(":");
            if (colonIndex == -1)
                continue;

            String name = header.substring(0, colonIndex).trim().toLowerCase();
            String value = header.substring(colonIndex + 1).trim();

            if (!distinctHeaderMap.containsKey(name)) {
                distinctHeaderMap.put(name, value);
            }
        }

        // 🧹 Remove excluded part
        List<String> newHeaders = new ArrayList<>();
        for (Map.Entry<String, String> entry : distinctHeaderMap.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (key.equals("request-line")) {
                newHeaders.add(value);
                continue;
            }

            if (excludedPart.type.equals("header") && key.equalsIgnoreCase(excludedPart.name)) {
                continue;
            }

            if (excludedPart.type.equals("cookie") && key.equals("cookie")) {
                String[] cookies = value.split(";");
                List<String> keptCookies = new ArrayList<>();
                for (String cookie : cookies) {
                    if (!cookie.trim().startsWith(excludedPart.name + "=")) {
                        keptCookies.add(cookie.trim());
                    }
                }
                if (!keptCookies.isEmpty()) {
                    newHeaders.add("Cookie: " + String.join("; ", keptCookies));
                }
                continue;
            }

            newHeaders.add(capitalize(key) + ": " + value);
        }

        // 🔍 Remove query param
        String firstLine = newHeaders.get(0);
        if (excludedPart.type.equals("query")) {
            int qIdx = firstLine.indexOf("?");
            if (qIdx != -1) {
                String path = firstLine.substring(0, qIdx);
                String query = firstLine.substring(qIdx + 1);
                List<String> keptParams = new ArrayList<>();
                for (String param : query.split("&")) {
                    if (!param.startsWith(excludedPart.name + "=")) {
                        keptParams.add(param);
                    }
                }
                firstLine = path + (keptParams.isEmpty() ? "" : "?" + String.join("&", keptParams));
                newHeaders.set(0, firstLine);
            }
        }

        // 🧯 Remove body
        if (excludedPart.type.equals("body")) {
            body = "";
        }

        return helpers.buildHttpMessage(newHeaders, body.getBytes());
    }

    private String capitalize(String input) {
        if (input == null || input.isEmpty())
            return input;
        return input.substring(0, 1).toUpperCase() + input.substring(1);
    }
}
