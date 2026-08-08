# Cookie Extractor (Research Tool)

> **Disclaimer:** This project was built **solely for educational and research purposes**.  
> It was created as a technical exercise to demonstrate how browser cookies can be extracted and decrypted using documented, publicly available Windows APIs.  
> **No criminal intent is involved.** The tool should only be used on systems you own or have explicit permission to test.

## Background

I was asked to research how browser cookie extraction works and to build a working proof-of-concept that could be shared on GitHub.  
I spent several days studying open‑source repositories that already tackled this problem.  
By combining and adapting code from those publicly available projects, I was able to assemble this script.

All components used here are open‑source and freely accessible on GitHub.  
This project does **not** introduce any novel exploitation technique; it merely automates what anyone with administrator rights can already do using native Windows features (DPAPI, COM elevation, etc.).

## What It Does

- Scans for installed Chromium‑based and Firefox‑family browsers.
- Extracts cookies from every profile, including those protected by Chrome’s **app‑bound (v20)** encryption.
- Decrypts the cookies using the system’s DPAPI keys (requires administrator privileges).
- Groups and reports all cookies, highlighting those likely to be login/session credentials.
- Uploads the report to a configurable HTTP endpoint (for research analysis).

## How to Run (Quick Start)

The script requires **Python 3.9+** and the dependencies listed in the inline metadata, but you **don’t need Python installed** if you use [`uv`](https://docs.astral.sh/uv/).

### On a machine **without** Python (one‑liner, as Administrator)

```powershell
