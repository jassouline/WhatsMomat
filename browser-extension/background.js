const WHATSMOMAT_BASE_URL = 'http://127.0.0.1:3000';

function escapeOmniboxXml(text) {
  return String(text || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

chrome.omnibox.onInputChanged.addListener(async (text, suggest) => {
  const query = String(text || '').trim();
  if (!query) return;
  try {
    const res = await fetch(
      `${WHATSMOMAT_BASE_URL}/api/opensearch-suggest?q=${encodeURIComponent(query)}`,
      { credentials: 'include' }
    );
    if (!res.ok) return;
    const [, completions = [], descriptions = []] = await res.json();
    const items = completions.slice(0, 6).map((comp, idx) => ({
      content: String(comp),
      description: `<match>${escapeOmniboxXml(comp)}</match> — <dim>${escapeOmniboxXml(descriptions[idx] || 'WhatsMomat')}</dim>`,
    }));
    suggest(items);
  } catch {
    // Ignore transient network errors when local portal is stopped
  }
});

chrome.omnibox.onInputEntered.addListener((text, disposition) => {
  const clean = String(text || '').trim();
  let targetUrl = `${WHATSMOMAT_BASE_URL}/`;
  if (clean.toLowerCase().startsWith('go/')) {
    const slug = clean.slice(3).replace(/[^a-zA-Z0-9_-]/g, '');
    targetUrl = `${WHATSMOMAT_BASE_URL}/go/${encodeURIComponent(slug)}`;
  } else if (clean) {
    targetUrl = `${WHATSMOMAT_BASE_URL}/?q=${encodeURIComponent(clean)}`;
  }

  if (disposition === 'newForegroundTab') {
    chrome.tabs.create({ url: targetUrl, active: true });
  } else if (disposition === 'newBackgroundTab') {
    chrome.tabs.create({ url: targetUrl, active: false });
  } else {
    chrome.tabs.update({ url: targetUrl });
  }
});
