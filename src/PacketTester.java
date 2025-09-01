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

            // ⏱️ Add delay after each request
            try {
                Thread.sleep(3000); // 3-second pacing
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
        List<String> headers = new ArrayList<>(requestInfo.getHeaders());
        int bodyOffset = requestInfo.getBodyOffset();
        String body = new String(Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length));

        // Remove excluded part
        List<String> newHeaders = new ArrayList<>();
        for (String header : headers) {
            if (excludedPart.type.equals("header")
                    && header.toLowerCase().startsWith(excludedPart.name.toLowerCase() + ":")) {
                continue;
            }
            if (excludedPart.type.equals("cookie") && header.toLowerCase().startsWith("cookie:")) {
                String cookieLine = header.substring(7).trim();
                String[] cookies = cookieLine.split(";");
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
            newHeaders.add(header);
        }

        // Remove query param
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

        // Remove body
        if (excludedPart.type.equals("body")) {
            body = "";
        }

        return helpers.buildHttpMessage(newHeaders, body.getBytes());
    }
}
