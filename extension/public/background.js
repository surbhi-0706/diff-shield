chrome.runtime.onMessage.addListener((message) => {
  if (
    typeof message !== "object" ||
    message === null ||
    message.type !== "DIFF_SHIELD_MALICIOUS_CHANGE"
  ) {
    return;
  }

  const finding = message.finding;
  if (
    typeof finding !== "object" ||
    finding === null ||
    typeof finding.id !== "string" ||
    typeof finding.title !== "string" ||
    typeof finding.repository !== "string" ||
    typeof finding.description !== "string"
  ) {
    console.error("Received an invalid malicious-change finding.");
    return;
  }

  chrome.storage.local.set(
    {
      latestThreat: {
        id: finding.id,
        title: finding.title,
        repository: finding.repository,
        description: finding.description,
        detectedAt: new Date().toISOString(),
      },
    },
    () => {
      if (chrome.runtime.lastError) {
        console.error(
          "Could not save the malicious-change finding:",
          chrome.runtime.lastError.message,
        );
      }
    },
  );
});
