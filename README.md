# Xbox Save Signing Key Generator

The original Xbox (2001) has cryptographically signed saves, to edit or manipulate them you need to be able to resign the save with the games unique key. This key is generated using 2 input sources, the master Xbox key and the games unique signing key.

**Xbox sav sig gui** is a small web UI built with [NiceGUI](https://nicegui.io) to generate the keys used for resigning saves from an `Xbox key` and `game key`. It also supports extracting the game key from an uploaded XBE file and downloading the generated signing key as raw bytes.

## Features

- Hex-validated input fields for Xbox key and game key
- Optional XBE upload to auto-extract the game key
- Multiple output formats for the signing key:
  - **Native**: first 16 bytes (32 hex chars)
  - **Raw**: full 20-byte HMAC-SHA1 digest (40 hex chars)
  - **XBTF**: first 16 bytes rendered as a C-style `0xNN, ...` array
- Copy-to-clipboard function for the generated signing key
- "Download Signing Key as Bytes" button to download the key as a binary file

## Running via a Docker container (recommended)

A simple Docker compose file is provided. Edit the `STORAGE_SECRET` before running.

### Run the container

```bash
docker compose up
```

Then open:

- <http://localhost:8080>

## Running natively

### Requirements

- Python 3.10+
- A virtual environment is recommended

### Setup steps

1. **Create and activate a virtual environment (optional but recommended)**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # on Windows: .venv\\Scripts\\activate
   ```

2. **Install dependencies**

   ```bash
   pip install nicegui
   ```

3. **Run the app**

   From the project root:

   ```bash
   python -m app.main
   ```

   Or, if you prefer to run the file directly:

   ```bash
   python app/main.py
   ```

4. **Open the UI**

   Visit:

   - <http://localhost:8080>

### Storage Secret

The app uses `app.storage.user` for per-user state. NiceGUI requires a `storage_secret` when this is used. The code will:

- Read `STORAGE_SECRET` from the environment if set, **otherwise**
- Fall back to a built-in default secret.

To override the secret locally:

```bash
export STORAGE_SECRET="some-long-random-string"
python app/main.py
```

## Notes

- This tool is intended for local / internal use, it should not be relied upon for running a hosted service accessible to the public.
- HMAC-SHA1 is used to match existing Xbox behavior; it is **not** recommended for new general-purpose cryptographic designs.
- XBE parsing is done in memory with simple size checks; invalid or too-small files will result in an error notification.
