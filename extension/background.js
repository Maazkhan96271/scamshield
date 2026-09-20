/**
 * ScamShield MV3 service worker — adds a right-click context menu:
 * select suspicious text anywhere → "Check selection with ScamShield".
 * Selection is passed to the popup via chrome.storage.session; no network.
 */

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scamshield-check-selection",
    title: "Check selection with ScamShield",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "scamshield-check-selection") return;
  const selection = (info.selectionText ?? "").trim();
  if (!selection) return;

  await chrome.storage.session.set({ pendingText: selection.slice(0, 8000) });
  if (tab?.windowId != null) {
    await chrome.action.openPopup?.().catch?.(() => {});
  }
});
