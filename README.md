# Safe Browsing Buddy

Safe Browsing Buddy is a beginner-friendly Chrome extension that helps users identify potentially suspicious websites and promotes safe browsing habits. All analysis is performed locally inside the browser — no data collection, transmission, or external APIs are used.

---

## Project overview

Safe Browsing Buddy inspects the URL of the currently active tab and performs a set of local heuristic checks to identify suspicious characteristics. It produces a risk score (0–100), explains which characteristics contributed to the risk, and provides practical safe-browsing recommendations.

This repository contains a complete, ready-to-load Chrome Extension built with Manifest V3, plain HTML/CSS/Vanilla JavaScript.

## Features

- Automatically reads the current tab's URL when the popup opens.
- Runs a local URL safety analysis for patterns such as:
  - IP addresses in place of domains
  - HTTP vs HTTPS
  - Excessive subdomains or long domains
  - Suspicious keywords in domains or paths
  - Excessive hyphens or punycode (xn--) domains
  - URL shorteners and obfuscated/long query strings
- Calculates a risk score (0–100) and maps it to Low / Suspicious / High risk levels.
- Shows detected reasons and recommended actions.
- Minimal permissions — all analysis runs locally.

## Technologies used

- Manifest V3 (Chrome extensions)
- HTML, CSS
- Vanilla JavaScript

## Project structure

- manifest.json — extension manifest (MV3)
- popup.html — popup UI
- popup.css — popup styling
- popup.js — popup logic and local analysis
- background.js — service worker (minimal)
- content.js — optional script injected to highlight suspicious links on the page
- icons/ — simple SVG icons used in the UI
- README.md — this file

## Installation / Loading into Chrome (Developer Mode)

1. Clone or download this repository.
2. Open Chrome and go to `chrome://extensions/`.
3. Enable **Developer mode** (top-right).
4. Click **Load unpacked** and select the project directory (the folder that contains `manifest.json`).
5. The extension should appear in your toolbar. Click the extension icon to open the popup and analyze the current site.

Note: When clicking "Highlight", the extension injects a small content script into the current page to visually mark links that look suspicious. This is done only when requested by the user.

## How the risk scoring system works

The analysis uses simple, transparent heuristics and assigns weights to each detected issue. The score sums the weights, applies small modifiers for certain trusted TLDs or short hostnames, and clamps the result to a 0–100 range.

Typical checks and example weights:

- IP address used instead of domain (weight 30)
- HTTP (not HTTPS) (weight 20)
- URL very long (weight 12)
- Excessive subdomains (weight 10)
- Suspicious keywords in domain or path (weights 6–8)
- URL shortener domain (weight 14)
- Punycode/IDN domain (weight 12)

Risk level mapping:
- 0–29: Low Risk — likely safe
- 30–59: Suspicious — proceed with caution
- 60–100: High Risk — avoid entering sensitive info

Important: This scoring is heuristic and intentionally conservative for educational/demo purposes. It is NOT a replacement for full threat intelligence.

## Privacy

- All analysis runs locally in your browser. No external servers or third-party services are called.
- The extension does not transmit, store, or sell browsing data.
- The extension requests only the minimum permissions required for functionality (`activeTab`, `scripting`).

## Limitations

- This tool uses simple heuristics and cannot detect all malicious sites.
- It may produce false positives or false negatives.
- It does not perform content-based scanning of remote resources.

## Future improvements

- Add an allowlist/ignore list accessible to the user.
- Provide more sophisticated pattern checks and community-sourced reputation data (with clear privacy controls).
- Optional local ML model (client-side) to improve accuracy.
- Polish UI animations and accessibility features.

## Security notes

- No remote code execution. No eval() used.
- The extension follows Manifest V3 security guidelines and performs all analysis locally.

---

If you use this project for a demo or assignment, please attribute the original author and mention that the extension is for educational purposes only.
