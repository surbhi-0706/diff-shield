# DIFF SHIELD browser extension

The extension popup provides a security dashboard and displays a persistent red
banner when it receives a malicious-change finding.

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
