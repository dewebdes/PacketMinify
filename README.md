# PacketMinify

**PacketMinify** is a Burp Suite extension that distills HTTP requests into their essential components—headers, cookies, query parameters, and body—by testing each part's impact on the response. It reconstructs a minimized packet and sends it to Repeater for further analysis.

Crafted by **Kave** & **Microsoft Copilot**, this tool treats packet reduction as a symbolic diagnostic ritual.

---

## 🔧 Features

- Context menu integration: Right-click any request → “Send to PacketMinify”
- Parses headers, cookies, query params, and body into symbolic parts
- Iteratively disables each part to test its impact on response status and length
- Reconstructs a minimized request using only essential parts
- Displays original and minimized packets in a custom Burp tab
- Sends minimized request to a new Repeater tab for live testing
- Detects cases where minimized packets fail to replicate original behavior — flagging them for deeper manual analysis

---

## 📦 Project Structure

```plaintext
PacketMinify/
├── src/
│   ├── BurpExtender.java
│   ├── MinifierEngine.java
│   ├── PacketExtractor.java
│   ├── PacketMinifier.java
│   ├── PacketMinifyTab.java
│   ├── PacketPart.java
│   ├── PacketTester.java
│   ├── RepeaterSender.java
│   ├── ResponseComparator.java
│   └── Utils.java
│
├── lib/
│   └── burp-extender-api-2.1.jar
│
├── build/
│   ├── PacketMinify.jar
│   ├── BurpExtender.class
│   ├── PacketExtractor.class
│   ├── PacketMinifier.class
│   ├── PacketMinifyTab.class
│   ├── PacketPart.class
│   ├── PacketTester.class
│   ├── RepeaterSender.class
│   ├── ResponseComparator.class
│   └── Utils.class
│
├── manifest.json
└── README.md
```

---

## ⚙️ Installation

1. **Clone or download the project**

2. **Compile the extension**

   ```bash
   javac -cp lib/burp-extender-api-2.1.jar -d build src/*.java
   $env:Path += ";C:\Program Files\Java\jdk-21\bin"
   jar cf build/PacketMinify.jar -C build .
   ```

3. **Load into Burp Suite**
   - Open Burp → Extender → Extensions → Add
   - Select **Extension type: Java**
   - Load `build/PacketMinify.jar`

---

## 🧙 Usage

1. In Burp's HTTP history or Repeater, right-click a request.
2. Select **Send to PacketMinify**.
3. Open the **PacketMinify** tab to view:
   - Original request
   - Minimized request
   - Logs of which parts were deemed essential
4. The minimized request is automatically sent to Repeater.

---

## 🧩 Logic

PacketMinify performs the following steps:

1. **Extract Parts**: Headers, cookies, query params, and body are parsed into `PacketPart` objects.
2. **Test Essentials**: Each part is temporarily removed and the modified request is sent. If the response changes, the part is marked essential.
3. **Reconstruct Request**: Only essential parts are used to rebuild the minimized packet.
4. **Dispatch to Repeater**: The minimized request is sent to a new Repeater tab for further inspection.
5. **Compare Responses**: If the minimized packet fails to replicate the original response, the extension flags the flow as “interesting” — suggesting deeper manual analysis.

---

## 🔍 Symbolic Analysis Mode

When the final minimized packet does **not** yield the same response as the original, PacketMinify enters a symbolic diagnostic mode. This often reveals **interdependent headers** like `Origin` and `Referer`, which may appear non-essential in isolation but are jointly required.

Such flows are ideal for **handy analysis**, allowing the user to:

- Observe fallback logic and header interdependence
- Decode server-side rituals and tolerance thresholds
- Refine attack logic based on symbolic packet behavior

---

## 🧠 Authors

- **Kave** — Mythic system architect and diagnostic ritualist
- **Microsoft Copilot** — Co-creative AI companion

---

## 📜 License

This project is released under the MIT License. Use it, adapt it, narrate it.
