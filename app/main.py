from nicegui import ui, events, app
import hashlib, hmac, os

_DEFAULT_STORAGE_SECRET = 'c6747ce3-6a56-48b8-95b8-04081b4e368f-7e24bd96-ae5a-46ec-b22c-4e153f98cfea'
_ENV_STORAGE_SECRET = os.environ.get('STORAGE_SECRET') or ''
_EFFECTIVE_STORAGE_SECRET = _ENV_STORAGE_SECRET or _DEFAULT_STORAGE_SECRET


STATE_KEY = 'xbox_signing_state'
DEFAULT_STATE = {
    'signature': '',
    'raw_signature': '',  # full 20-byte HMAC as hex
    'gameKey': 'E34B1AE87CDE555DC5A5CC7E30DDAACE', # default game key for testing, can be replaced by user input or XBE upload
    'xboxKey': '5C0733AE0401F7E8BA7993FDCD2F1FE0', # default xbox key, can be replaced by user input
    'outputFormat': 1, # 1=Native (first 16 bytes), 2=Raw (full 20 bytes), 3=XBTF (first 16 bytes in C array format)
}


def get_state() -> dict:
    """
    Return per-client visit state stored in app.storage.client.

    Uses NiceGUI's ``app.storage.client`` to keep each browser visit's keys
    and signatures isolated. Data is kept only for the duration of the
    current page visit and is not persisted across reloads or new tabs.
    """
    client_storage = app.storage.client
    if STATE_KEY not in client_storage:
        client_storage[STATE_KEY] = DEFAULT_STATE.copy()
    return client_storage[STATE_KEY]


def root():
    """
    Root view used by ui.run()

    Create and render the main user interface for the Xbox Signing Key Generator.
    
    This function builds the application's root UI layout, which includes:
    - Input fields for Xbox Key and Game Key (with hex validation)
    - File upload functionality for XBE files to extract Game Key
    - Output format toggle (Native/Raw/XBTF)
    - 'Generate' button to create signing keys
    - Display area for generated signatures with copy-to-clipboard functionality
    - Save button to export signature as bytes
    
    The UI components are bound to application state and trigger signature
    generation based on user interactions.
    """
    state = get_state()
    with ui.card():
        ui.label('Xbox Save Signing Key Generator')
        with ui.row():
            xboxKey = ui.input(
                label='Xbox Key',
                placeholder='Xbox key',
                value=state['xboxKey'],
                validation={'Only hex digits are allowed': lambda v: (v is None) or all(c in '0123456789abcdefABCDEF' for c in v)},
            ).props('clearable')
            xboxKey.props('size=32')   
            xboxKey.style('max-width:100%;')
            xboxKey.bind_value(state, 'xboxKey')

            gameKey = ui.input(
                label='Game Key',
                placeholder='Game key',
                value=state['gameKey'],
                validation={'Only hex digits are allowed': lambda v: (v is None) or all(c in '0123456789abcdefABCDEF' for c in v)},
            ).props('clearable')
            gameKey.props('size=32')
            gameKey.style('max-width:100%;')
            gameKey.bind_value(state, 'gameKey')
        with ui.expansion('Optional: Upload XBE to get Game Key from file', icon='info', value=False):
            ui.upload(on_upload=handle_upload) \
                .classes('max-w-full') \
                .props('accept=.xbe')
            ui.label('You can skip this and type the Game Key manually.') \
                .classes('text-sm text-gray-500')

        ui.label('Output Format:')
        outputFormat = ui.toggle({1: 'Native', 2: 'Raw', 3: 'XBTF'}, value=state['outputFormat']).on_value_change(
            lambda: generate_signature(xboxKey.value, gameKey.value, outputFormat.value)
        )

        ui.label('')
        ui.button('Generate', on_click=lambda: generate_signature(xboxKey.value, gameKey.value, outputFormat.value))
        ui.label('Generated Save Signing Key:')
        # with ui.row(align_items='baseline'):
        with ui.row():
            ui.label('').bind_text_from(state, 'signature').style('width:400px; height:100px; border:1px solid #ccc; padding:10px;').props('id=sigKeyLabel')
            ui.icon('content_copy').props('size=24').style('cursor:pointer;').on('click', js_handler='''
                async () => {
                    const el = document.getElementById("sigKeyLabel");
                    if (el) {
                        try {
                            await navigator.clipboard.writeText(el.innerText);
                            emitEvent("clipboardwrite", "Copied " + el.innerText + " to clipboard.");
                        } catch (err) {
                            emitEvent("clipboardwrite", "Failed to copy: " + err);
                        }
                    } else {
                        emitEvent("clipboardwrite", "Element not found");
                    }
                }
            ''')
            ui.on('clipboardwrite', lambda e: ui.notify(e.args))
        ui.button('Download Signing Key as Bytes', on_click=save_signature_bytes)

        # Footer attribution
        with ui.column().classes('w-full items-end gap-0'):
              ui.label('Powered by code from').classes('text-sm text-gray-500')
              ui.link('www.ps2savetools.com', 'https://www.ps2savetools.com').classes('text-sm text-blue-500')
            

async def handle_upload(e: events.UploadEventArguments):
    """
    Handle the upload of an XBE file and extract its signature key and game title.

    This async function processes an uploaded XBE file, extracts the game's signature key
    and title, validates the extraction, and updates the application state with the game key.

    Args:
        e (events.UploadEventArguments): Upload event containing the file data.

    Returns:
        None: Returns early if the XBE file is invalid (m_sig_key is None).

    Side Effects:
        - Displays a UI notification with the game title and key upon successful extraction.
        - Updates the application state with the extracted game key (first 32 characters).
        - Clears the xbeFile variable to free memory.

    Note:
        The game title is decoded with error replacement to handle invalid UTF-8 characters.
        If extraction fails, the function returns silently without notification.
    """
    xbeFile = await e.file.read()
    m_sig_key, gameTitle  = getKeyfromXBEinMem(xbeFile)
    if m_sig_key is None:
        # ui.notify('Invalid XBE file. Could not extract game key.', color='negative')
        return
    try:
        title_text = gameTitle.decode('utf-8', errors='replace').strip()
    except Exception:
        title_text = '<invalid title>'
    ui.notify(f'File uploaded successfully! Game Title: {title_text} Game Key: {m_sig_key.hex().upper()}')
    state = get_state()
    state['gameKey'] = m_sig_key.hex().upper()[:32]
    xbeFile = None

def _is_hex(s: str) -> bool:
    """
    Return True if the string consists only of hexadecimal characters.

    Accepts both upper and lower-case hex digits; empty or None values are
    considered invalid and return False.
    """
    return bool(s) and all(c in '0123456789abcdefABCDEF' for c in s)

def generate_signature(xbox_key, game_key, output_format):
    """
    Generate and store the signing key for the current Xbox and game keys.

    Validates the provided keys, derives the HMAC-SHA1 signature, formats it
    according to the selected output format, and updates the per-user state
    with both the raw and formatted signature.
    """
    if not xbox_key:
        ui.notify('Xbox Key cannot be blank', color='negative')
        return
    if not game_key:
        ui.notify('Game Key cannot be blank', color='negative')
        return
    if not _is_hex(xbox_key) or not _is_hex(game_key):
        ui.notify('Keys must be valid hex.', color='negative')
        return

    key = generateKey(bytes.fromhex(xbox_key), bytes.fromhex(game_key))
    state = get_state()
    state['raw_signature'] = key  # store full hex digest (40 chars)
    state['outputFormat'] = output_format
    formatted_key = formatSigKey(key, output_format)
    state['signature'] = formatted_key


def save_signature_bytes(filename: str = 'signaturekey.bin'):
    """
    Trigger a browser download of the generated signature key as raw bytes.

    Length of bytes written is determined by the output format.
    """
    state = get_state()
    sig_hex = state.get('raw_signature') or ''
    if not sig_hex:
        ui.notify('No signature generated to save.', color='negative')
        return

    fmt = state.get('outputFormat', 1)

    # choose how many bytes to export based on the selected output format
    if fmt == 1:  # Native: first 16 bytes (32 hex chars)
        needed_hex_len = 32
        sig_hex_to_use = sig_hex[:needed_hex_len]
    elif fmt == 2:  # Raw: full 20-byte HMAC (40 hex chars)
        needed_hex_len = 40
        sig_hex_to_use = sig_hex[:needed_hex_len]
    elif fmt == 3:  # XBTF: 16 bytes (same as Native)
        needed_hex_len = 32
        sig_hex_to_use = sig_hex[:needed_hex_len]
    else:
        needed_hex_len = 40
        sig_hex_to_use = sig_hex

    if len(sig_hex) < needed_hex_len:
        ui.notify('Current signature is shorter than expected for this format.', color='negative')
        return

    try:
        sig_bytes = bytes.fromhex(sig_hex_to_use)
    except ValueError:
        ui.notify('Current signature is not valid hex.', color='negative')
        return

    # send bytes to the browser as a download instead of saving on the server
    ui.download.content(sig_bytes, filename)
    ui.notify(f'Signature download started: {filename}', color='positive')

def generateKey(xkey, gkey):
    """
    Compute the HMAC-SHA1 signing key from the given Xbox and game keys.
    """
    sigKey = hmac.new(xkey, gkey, hashlib.sha1)
    return sigKey.hexdigest()

def formatSigKey(rawsig, formatting):
    """
    Format a raw hex signature string according to the selected output.

    formatting:
        1 -> first 16 bytes as upper-case hex (32 chars)
        2 -> full 20 bytes as upper-case hex (40 chars)
        3 -> first 16 bytes as a C-style 0xNN, ... array (upper-case)
    """
    if formatting == 1:
        return rawsig[:32].upper()

    elif formatting == 2:
        return rawsig.upper()

    elif formatting == 3:
        returnstring = ''
        y = 0
        for x in range(0,15):
            returnstring = returnstring + '0x' + rawsig[y:y+2] +  ', '
            y = y + 2
        returnstring = returnstring + '0x' + rawsig[y:y+2]
        return returnstring.upper()
    
    
# def getKeyfromXBE(xbefile):
#     f = open(xbefile, "rb")
#     try:
#         #move to base address
#         f.seek(260, 0)
#         base = f.read(4)

#         #move to cert address
#         f.seek(280,0)
#         cert = f.read(4)

#         #get the location of the cert
#         certAddress = unpack("i", cert)
#         baseAddress = unpack("i", base)
#         loc = certAddress[0] - baseAddress[0]

#         #move to the title
#         f.seek(loc + 12, 0)
#         gameTitle = f.read(128)

#         #move to the sigkey
#         f.seek(loc + 192, 0)
#         m_sig_key = f.read(16)

#     finally:
#         f.close()
#         return m_sig_key, gameTitle

def getKeyfromXBEinMem(xbeData):
    """
    Extract game title and signature key directly from an XBE file in memory.

    Performs basic size checks before reading header fields, then returns the
    16-byte signature key and 128-byte title text from the XBE certificate.

    Error condition:
    Returns (None, None) and notifies the user if the data is too short.
    """
    #validate that the file is large enough to contain the necessary data
    if len(xbeData) < 284:
        ui.notify('Invalid XBE file. File is too small to contain necessary data.', color='negative')
        return None, None
    
    #move to base address
    base = xbeData[260:264]

    #move to cert address
    cert = xbeData[280:284]

    #get the location of the cert
    certAddress = int.from_bytes(cert, byteorder='little')
    baseAddress = int.from_bytes(base, byteorder='little')
    loc = certAddress - baseAddress

    #further validate that the file is large enough to contain the necessary data
    if len(xbeData) < (loc + 208):
        ui.notify('Invalid XBE file. File is too small to contain necessary data.', color='negative')
        return None, None

    #move to the title
    gameTitle = xbeData[loc + 12:loc + 140]

    #move to the sigkey
    m_sig_key = xbeData[loc + 192:loc + 208]

    return m_sig_key, gameTitle 

ui.run(
    root,
    title='Xbox Signing Key Generator',
    reload=False,
    dark=None,
    storage_secret=_EFFECTIVE_STORAGE_SECRET,
)