package burp;

import java.awt.Component;
import java.util.List;
import java.util.ArrayList;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;

public class PacketMinifyTab implements IMessageEditorTab {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final IMessageEditorController controller;
    private final boolean isRequest;
    private final JTextArea textArea;
    private byte[] currentMessage;

    public PacketMinifyTab(IBurpExtenderCallbacks callbacks, IMessageEditorController controller, boolean isRequest) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.controller = controller;
        this.isRequest = isRequest;
        this.textArea = new JTextArea();
    }

    @Override
    public String getTabCaption() {
        return "PacketMinify";
    }

    @Override
    public Component getUiComponent() {
        return new JScrollPane(textArea);
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return isRequest;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.currentMessage = content;
        if (content == null || !isRequest) {
            textArea.setText("");
            return;
        }

        // Start dispatch loop in a separate thread
        new Thread(() -> {
            IHttpService service = controller.getHttpService();
            List<byte[]> variants = generateVariants(content);

            for (int i = 0; i < variants.size(); i++) {
                byte[] candidate = variants.get(i);
                IHttpRequestResponse response = callbacks.makeHttpRequest(service, candidate);

                // Wait until response is valid
                while (response == null || response.getResponse() == null || response.getResponse().length == 0) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }

                // Delay after each request
                textArea.append("Sleeping before next dispatch...\n");
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    textArea.append("Thread interrupted during delay: " + e.getMessage() + "\n");
                    return;
                }
                textArea.append("Woke up, continuing...\n");

                textArea.append("Dispatched variant " + (i + 1) + " with delay.\n");
            }

            textArea.append("All variants dispatched with pacing.\n");
        }).start();
    }

    @Override
    public byte[] getMessage() {
        return currentMessage;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return null;
    }

    // Example variant generator — replace with symbolic logic
    private List<byte[]> generateVariants(byte[] original) {
        List<byte[]> variants = new ArrayList<>();
        variants.add(original); // Variant 1: original
        // Add more variants here (e.g. stripped headers, altered cookies)
        return variants;
    }
}
