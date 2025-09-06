import os
import json
import hashlib
import time
import re
from urllib.parse import urlparse
import mimetypes

import requests


DIR = "Fetched_Images"
HASH_FILE = os.path.join(DIR, "hashes.json")
MAX_BYTES = 50 * 1024 * 1024  # 50 MB safety limit


def load_hashes():
    if os.path.exists(HASH_FILE):
        try:
            with open(HASH_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_hashes(hashes):
    try:
        with open(HASH_FILE, "w", encoding="utf-8") as f:
            json.dump(hashes, f, indent=2)
    except Exception:
        pass


def sanitize_filename(name: str) -> str:
    # Remove query strings and unsafe characters
    name = name.split("?")[0]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name.strip("._-") or "downloaded_image"


def filename_from_cd(cd: str) -> str:
    # Content-Disposition: attachment; filename="fname.ext"
    if not cd:
        return None
    m = re.search(r'filename\*=UTF-8\\''([^\n]+)', cd)
    if m:
        return m.group(1)
    m = re.search(r'filename=(?:"?)([^";]+)', cd)
    if m:
        return m.group(1)
    return None


def ext_from_content_type(ct: str) -> str:
    if not ct:
        return ".jpg"
    ext = mimetypes.guess_extension(ct.split(";")[0].strip())
    if ext:
        return ext
    # fallback common types
    if ct.startswith("image/png"):
        return ".png"
    if ct.startswith("image/jpeg"):
        return ".jpg"
    if ct.startswith("image/gif"):
        return ".gif"
    return ".jpg"


def compute_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def choose_filename(url: str, resp) -> str:
    # Try Content-Disposition first
    cd = resp.headers.get("content-disposition")
    fname = filename_from_cd(cd)
    if fname:
        fname = sanitize_filename(fname)
        return fname

    parsed = urlparse(url)
    basename = os.path.basename(parsed.path)
    if basename:
        basename = sanitize_filename(basename)
        if "." in basename:
            return basename
        # missing extension -> use content-type
        ext = ext_from_content_type(resp.headers.get("content-type", ""))
        return basename + ext

    # fallback: timestamp + ext
    ext = ext_from_content_type(resp.headers.get("content-type", ""))
    return f"downloaded_{int(time.time())}{ext}"


def save_image(content: bytes, filename: str) -> str:
    os.makedirs(DIR, exist_ok=True)
    path = os.path.join(DIR, filename)
    base, ext = os.path.splitext(filename)
    i = 1
    # Avoid overwriting files with different content
    while os.path.exists(path):
        path = os.path.join(DIR, f"{base}_{i}{ext}")
        i += 1
    with open(path, "wb") as f:
        f.write(content)
    return path


def fetch_single(url: str, hashes: dict) -> None:
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()

        # Check headers
        ctype = resp.headers.get("content-type", "")
        if not ctype.startswith("image"):
            print(f"✗ Skipped (not an image): {url} — Content-Type: {ctype}")
            return

        # Optional safety: check size if header present
        clen = resp.headers.get("content-length")
        if clen is not None:
            try:
                if int(clen) > MAX_BYTES:
                    print(f"✗ Skipped (file too large): {url} — {clen} bytes")
                    return
            except Exception:
                pass

        content = resp.content
        if len(content) > MAX_BYTES:
            print(f"✗ Skipped (file too large after download): {url} — {len(content)} bytes")
            return

        h = compute_hash(content)
        if h in hashes:
            print(f"✓ Duplicate detected, already have: {hashes[h]}")
            return

        filename = choose_filename(url, resp)
        saved = save_image(content, filename)

        hashes[h] = os.path.basename(saved)
        save_hashes(hashes)

        print(f"✓ Successfully fetched: {os.path.basename(saved)}")
        print(f"✓ Image saved to {saved}")

    except requests.exceptions.RequestException as e:
        print(f"✗ Connection error for {url}: {e}")
    except Exception as e:
        print(f"✗ An error occurred for {url}: {e}")


def parse_input(s: str):
    # Allow comma, whitespace or newline separated URLs
    parts = re.split(r"[,\n\s]+", s.strip())
    return [p.strip() for p in parts if p.strip()]


def main():
    print("Welcome to the Ubuntu Image Fetcher")
    print("A tool for mindfully collecting images from the web\n")

    raw = input("Please enter one or more image URLs (comma or newline separated):\n")
    urls = parse_input(raw)
    if not urls:
        print("No URLs provided. Exiting.")
        return

    os.makedirs(DIR, exist_ok=True)
    hashes = load_hashes()

    for url in urls:
        if not url.lower().startswith(("http://", "https://")):
            print(f"✗ Invalid URL (must start with http:// or https://): {url}")
            continue
        fetch_single(url, hashes)

    print("\nConnection strengthened. Community enriched.")


if __name__ == "__main__":
    main()
