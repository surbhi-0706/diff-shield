# DIFF SHIELD browser extension

The extension popup provides a security dashboard and displays a persistent red
banner when it receives a malicious-change finding.

## Build and load the extension

The browser must load the compiled extension directory. From the repository
root, run:

```bash
cd extension
npm install
npm run build
```

Then open the browser's extensions page, enable developer mode, choose **Load
unpacked**, and select:

```text
extension/dist
```

Do not select the repository root, `extension`, or `extension/public`.
`manifest.json` is copied from `extension/public` to `extension/dist` by Vite
when `npm run build` completes.

## Sending a malicious-change finding

The extension does not currently include a code scanner. A scanner or trusted
extension component must send findings to the background service worker with
this message shape:

```js
chrome.runtime.sendMessage({
  type: "DIFF_SHIELD_MALICIOUS_CHANGE",
  finding: {
    id: "DS-123",
    title: "Possible vulnerability reintroduction",
    repository: "owner/repository",
    description: "A previously fixed security issue may have returned.",
  },
});
```

The background worker validates and stores the latest finding. The popup shows
the red alert banner while open and restores it the next time it is opened.
Dismissal clears the stored finding.
