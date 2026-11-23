# DeSlop (Chrome / Edge / Brave, Windows)
A browser extension can't talk to Defender directly, so it uses a
local helper (host) that runs Defender's own MpCmdRun.exe.

---

### Installation
1. Open chrome://extensions, edge://extensions or brave://extensions, turn on Developer mode,
click "Load unpacked" and select the "extension" folder.
2. Copy the extension ID from the extension card.
3. Run host\install.bat and paste the ID in the following window.
4. Reload the page and click the extension icon.

---

### Usage

- "Choose files..." : opens a file picker ;

- "Choose a folder..." : opens a file picker that'll scan all the files present in a folder with a live count of the folder scanned and the total folders.
  Note : live count cannot be applied for big folders (\~500+ files) ; 

- Paste a full path ;  

- Press "Scan" next to a recent download.

- Paste a link into "Scan a link":  
  The helper downloads it into a temporary folder (never opened or run),
  scans it with Defender, then deletes it. Tick "Save to Downloads if clean"
  to keep that exact scanned copy. Limit: 1GB ; links that need a login
  will not work.

- Drag'n'Drop : Drag and drop

>[!WARNING]
>**Files are only reported, not deleted or quarantined.**

<br>

**Developer Note:**
"I did not speak (even a little bit) Portuguese before making this extension. The "Português" translation may not be accurate. If you have any issues with this translation (or any other one) i would likely ask you to report it to me"

<br>

**Errors:**
Exception when calling "GetResponse" with "0" argument(s): "The remote server returned an error: (403) Forbidden." if you see this error, it means that the site deliberately refused to grant access to a scan. This doesn't (necessarily) mean that the site is malicious.