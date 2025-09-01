package burp;

public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Packet Minifier");

        callbacks.registerMessageEditorTabFactory(new IMessageEditorTabFactory() {
            @Override
            public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean isRequest) {
                return new PacketMinifyTab(callbacks, controller, isRequest);
            }
        });
    }
}
