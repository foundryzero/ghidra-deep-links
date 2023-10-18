<p align="center">
  <img src="img/ghidra-deep-links-logo.png" alt="ghidra deep links logo"/>
</p>

# Ghidra Deep Links
A cross-platform plugin for Ghidra that provides deep linking support. This enables the generation of clickable `disas://` links that can be included in 3rd party applications. Example use cases include:
* Direct linking from research notes or reports to relevant binary locations.
* Sharing an interesting section address with peers over Slack, Discord, Teams etc.
* Including links in vulnerability write-ups or tutorials to direct readers to the exact address of an issue.

The linking mechanism will work across different project structures and with both shared and non-shared Ghidra projects.

# IDA support

Don't use Ghidra? Not a problem...

We have collaborated with the team behind Heimdallr, a plugin that provides deep linking support for IDA, on a new platform-agnostic URI schema so that links generated in Ghidra Deep Links can be opened by Heimdallr and vice versa. This assumes the exact same binary is loaded on both platforms. This is great as now teams can use their prefered disassembler while being able to use the same external notes and reference links. Check out Heimdallr over at: https://github.com/interruptlabs/heimdallr-ida

We invite other developers to adopt the `disas://` schema outlined in [URL format](#url-format) to enable more cross-application compatibility.

# ▶️ Usage
With a CodeBrowser tool open, right click on a line in the listing view which will present a new context menu items, "Copy Deep Link"

![The context menu in a Ghidra code listing containing the new Copy Deep Link item](img/context-menu.png)

Click on this menu item and a `disas://` link will be added to the clipboard. This can be shared by pasting like any normal link.

When you (or somebody else) clicks on the link the referenced binary will open in a CodeBrowser session and the memory address from the link will be jumped to.

> ⚠️ Currently the link handler does not distinguish between projects, and (on non-linux platforms) it cannot open Ghidra by itself. Therefore you will need to have Ghidra open and the project containing the binary referenced in the link open.

# ⚙️ Installation
### Linux
1. Download and install the latest release of the ghidra-deep-links extension from https://github.com/foundryzero/ghidra-deep-links/releases

2. Install the `disas://` handler by executing the following:

    (Before curling and executing random scripts from the internet it is a good idea to validate they don't do anything malicious. Please review the contents of this script before execution at `install.sh`)
    ```
    bash -c "$(curl https://raw.githubusercontent.com/foundryzero/ghidra-deep-links/main/install.sh)"
    ```

3. Alternatively, clone this repo and run `install-offline.sh`.

3. Follow the instructions in [Plugin Activation](#plugin-activation) to complete the install.


### Windows

1. Download and install the latest release of the ghidra-deep-links extension from https://github.com/foundryzero/ghidra-deep-links/releases

2. Install the `disas://` handler by executing the following in a PowerShell window:

    (Before executing random PowerShell scripts from the internet it is a good idea to validate they don't do anything malicious. Please review the contents of this script before execution at `install.ps1`)
    ```
    Invoke-Expression (Invoke-WebRequest https://raw.githubusercontent.com/foundryzero/ghidra-deep-links/main/install.ps1).Content 
    ```

3. Alternatively, clone this repo and run `install-offline.ps1`.

4. Follow the instructions in [Plugin Activation](#plugin-activation) to complete the install.


### Mac

1. Download and install the latest release of the ghidra-deep-links extension from https://github.com/foundryzero/ghidra-deep-links/releases

2. Additionally download `GhidraDeepLinksHandler.dmg` from the above releases page, mount the dmg and install the handler app as normal (drag to Applications)

3. Run the following to disable Gatekeeper on the handler app.
    
    (This is required as we do not code sign our releases. Please review the code at `os/mac`. This can be compiled from source by following the steps in `.github/workflows/mac_app.yml`)
    ```
    xattr -d com.apple.quarantine /Applications/GhidraDeepLinksHandler.app
    ```

4. Follow the instructions in Plugin Activation below.

## Plugin Activation

1. From the Ghidra project browser click `File -> Install Extensions`. Click the green `+` button and select the extension downloaded from the releases page (Don't extract the zip archive).

![](img/install.png)

2. In the main ghidra window (the one that shows your project files), go to `File -> Configure -> Utility` and enable `ghidra-deep-links`.

![](img/configure.png)

3. In a CodeBrowser window, go to `File -> Configure -> Utility` and enable `DeepLinksToolPlugin`.

4. Verify the extension is correctly installed by loading a project then visiting [disas://?ghidra_verify=true](disas://?ghidra_verify=true). This should open a dialog box in Ghidra.

# 🔨 Building

See [BUILDING.md](./BUILDING.md)


# 🔗 URL format

The URLs take the format

```
disas://<hash>/[?ghidra_path=<path>]&offset=<offset>[&label=<label>]
```

* `<hash>` is the MD5 hash of the binary
* `<ghidra_path>` is an optional location of the binary within a Ghidra project structure. It is used to speed up finding the binary of interest.
* `<offset>` is a memory address to jump to.
* `<label>` is the label associated with the offset if one is set. (For visual reference only)

If `<path>` cannot be found or does not match `<hash>`, the entire project will be searched for files that match `<hash>`, ignoring `<path>` entirely. This is to allow for differing project structures containing the same files and compatibility with `disas://` links generated by other applications, but can be quite slow in large projects.

Please consider adopting this schema when you want to create links to a location in a binary.

# ⚠️ Caveats & Known Issues

* `disas://` links cannot be opened from Snap applications.
* If multiple instances of ghidra are open, only the first will recieve the link requests.
* Currently the link handler does not distinguish between projects, and (on non-linux platforms) it cannot open Ghidra by itself. Therefore you will need to have Ghidra open and the project containing the binary referenced in the link open.
* When the link handler falls back to lookup by hash links may take a few seconds to open on projects with many (i.e. hundreds of) binaries.
* On Windows a Powershell window may briefly flash open on each link press.
