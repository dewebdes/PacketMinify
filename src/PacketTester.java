import burp.*;
import java.util.*;

public class PacketTester {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse originalMessage;
    private List<PacketPart> parts;
    private byte[] originalRequest;
    private byte[] originalBodyBytes;
    private byte[] originalResponse;
    private int originalStatus;

    public PacketTester(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
            IHttpRequestResponse originalMessage, List<PacketPart> parts) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.originalMessage = originalMessage;
        this.parts = parts;
        this.originalRequest = originalMessage.getRequest();

        IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);
        int bodyOffset = requestInfo.getBodyOffset();
        this.originalBodyBytes = Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length);

        IHttpService service = originalMessage.getHttpService();
        this.originalResponse = callbacks.makeHttpRequest(service, originalRequest).getResponse();
        IResponseInfo responseInfo = helpers.analyzeResponse(originalResponse);
        this.originalStatus = responseInfo.getStatusCode();
    }

    public List<PacketPart> identifyEssentialParts() {
        for (PacketPart part : parts) {
            part.essential = false;

            byte[] modifiedRequest = buildModifiedRequest(part);
            IHttpService service = originalMessage.getHttpService();
            byte[] response = callbacks.makeHttpRequest(service, modifiedRequest).getResponse();

            if (response == null || response.length == 0) {
                callbacks.printError("No response received for part: " + part.name);
                continue;
            }

            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            int status = responseInfo.getStatusCode();

            boolean changed = ResponseComparator.isEssentialChange(originalResponse, response, originalStatus, status);
            part.essential = changed;

            callbacks.printOutput(String.format("Tested %s: %s (%s) = %s | status: %d → %d | essential: %s",
                    part.type, part.name, normalize(part.name), part.type.equals("body") ? "(binary)" : part.value,
                    originalStatus, status, part.essential));

            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                callbacks.printError("Thread interrupted during delay: " + e.getMessage());
                break;
            }
        }

        byte[] minimizedRequest = buildFinalRequest();
        String host = originalMessage.getHttpService().getHost();
        RepeaterSender.sendToRepeater(callbacks, helpers, minimizedRequest, host);

        return parts;
    }

    private byte[] buildModifiedRequest(PacketPart excludedPart) {
        IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);
        List<String> rawHeaders = requestInfo.getHeaders();

        Map<String, String> distinctHeaderMap = new LinkedHashMap<>();
        String requestLine = rawHeaders.get(0);
        distinctHeaderMap.put("request-line", requestLine);

        for (int i = 1; i < rawHeaders.size(); i++) {
            String header = rawHeaders.get(i);
            int colonIndex = header.indexOf(":");
            if (colonIndex == -1)
                continue;

            String name = normalize(header.substring(0, colonIndex));
            String value = header.substring(colonIndex + 1).trim();

            if (!distinctHeaderMap.containsKey(name)) {
                distinctHeaderMap.put(name, value);
            }
        }

        List<String> newHeaders = new ArrayList<>();
        for (Map.Entry<String, String> entry : distinctHeaderMap.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (key.equals("request-line")) {
                newHeaders.add(value);
                continue;
            }

            if (excludedPart.type.equals("header") && normalize(key).equals(normalize(excludedPart.name))) {
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

        byte[] bodyBytes = excludedPart.type.equals("body") ? new byte[0] : originalBodyBytes;
        return helpers.buildHttpMessage(newHeaders, bodyBytes);
    }

    private byte[] buildFinalRequest() {
        IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);
        List<String> rawHeaders = requestInfo.getHeaders();

        Map<String, String> headerMap = new LinkedHashMap<>();
        String requestLine = rawHeaders.get(0);
        headerMap.put("request-line", requestLine);

        for (int i = 1; i < rawHeaders.size(); i++) {
            String header = rawHeaders.get(i);
            int colonIndex = header.indexOf(":");
            if (colonIndex == -1)
                continue;

            String name = normalize(header.substring(0, colonIndex));
            String value = header.substring(colonIndex + 1).trim();

            if (!headerMap.containsKey(name)) {
                headerMap.put(name, value);
            }
        }

        List<String> newHeaders = new ArrayList<>();
        for (Map.Entry<String, String> entry : headerMap.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (key.equals("request-line")) {
                newHeaders.add(value);
                continue;
            }

            if (key.equals("cookie")) {
                List<String> keptCookies = new ArrayList<>();
                for (String cookie : value.split(";")) {
                    String trimmed = cookie.trim();
                    String cookieName = trimmed.split("=")[0];
                    boolean keep = parts.stream()
                            .anyMatch(p -> p.essential && p.type.equals("cookie") && trimmed.startsWith(p.name + "="));
                    if (keep)
                        keptCookies.add(trimmed);
                }
                if (!keptCookies.isEmpty()) {
                    newHeaders.add("Cookie: " + String.join("; ", keptCookies));
                }
                continue;
            }

            boolean isEssential = parts.stream()
                    .filter(p -> p.essential && p.type.equals("header"))
                    .anyMatch(p -> normalize(p.name).equals(key));

            if (isEssential) {
                newHeaders.add(capitalize(key) + ": " + value);
            }
        }

        String firstLine = newHeaders.get(0);
        int qIdx = firstLine.indexOf("?");
        if (qIdx != -1) {
            String path = firstLine.substring(0, qIdx);
            String query = firstLine.substring(qIdx + 1);
            List<String> keptParams = new ArrayList<>();
            for (String param : query.split("&")) {
                String name = param.split("=")[0];
                boolean keep = parts.stream()
                        .anyMatch(p -> p.essential && p.type.equals("query") && p.name.equals(name));
                if (keep)
                    keptParams.add(param);
            }
            firstLine = path + (keptParams.isEmpty() ? "" : "?" + String.join("&", keptParams));
            newHeaders.set(0, firstLine);
        }

        byte[] bodyBytes = parts.stream().anyMatch(p -> p.essential && p.type.equals("body"))
                ? originalBodyBytes
                : new byte[0];

        return helpers.buildHttpMessage(newHeaders, bodyBytes);
    }

    private String capitalize(String input) {
        if (input == null || input.isEmpty())
            return input;
        return input.substring(0, 1).toUpperCase() + input.substring(1);
    }

    private String normalize(String input) {
        return input == null ? "" : input.trim().toLowerCase();
    }
}
