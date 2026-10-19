# KeyCrypt — Secure Password & Passphrase Generator

A fully offline, cryptographically secure password and passphrase generator. No frameworks, no dependencies, no server calls.

## Features

- **Generator** — Two modes: random passwords and word-based passphrases
- **Strength Checker** — Paste any password to see its entropy, crack time, and criteria breakdown
- **Security Tips** — Best practices including passphrase guidance
- **History** — Session-based log of all generated passwords and passphrases (cleared on page close)

## Security

- Uses `crypto.getRandomValues()` — the browser's CSPRNG, not `Math.random()`
- 100% client-side. Nothing is transmitted.
- Entropy shown in bits, crack time based on 1 trillion guesses/second

## Password Presets

| Preset   | Length | Charset         | Use case            |
|----------|--------|-----------------|---------------------|
| PIN      | 6      | Numbers only    | Device unlock PINs  |
| Wi-Fi    | 12     | Alphanumeric    | Router passwords    |
| Standard | 16     | Full            | Most websites       |
| Strong   | 24     | Full            | Banking, email      |
| Maximum  | 48     | Full, no repeat | Encryption keys     |

## Passphrase Mode

Generates memorable word-based passphrases using a curated 500+ word list.

| Option      | Description                                   |
|-------------|-----------------------------------------------|
| Word count  | 3–8 words (4 recommended minimum)             |
| Separator   | Hyphen, dot, underscore, space, random, none  |
| Capitalize  | Title-cases each word (Apple-Brook-Cedar)     |
| Append number | Adds a 4-digit random number at the end    |

### Style examples

| Style      | Example                              | Entropy |
|------------|--------------------------------------|---------|
| Classic    | `apple-brook-cedar-4271`             | ~60 bits|
| Title-dot  | `Apple.Brook.Cedar.Drift`            | ~56 bits|
| Long & safe| `apple_brook_cedar_drift_ember_8312` | ~73 bits|
| Random sep | `Apple~Brook!Cedar@5519`             | ~63 bits|

## Usage

Open `index.html` in any modern browser. No build step required.

## Files

```
index.html   — App shell and markup
style.css    — Dark theme design system
app.js       — Password/passphrase logic and UI behaviour
README.md    — This file
```
