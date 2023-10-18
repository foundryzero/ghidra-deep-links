package deeplinks;

import java.awt.Window;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.IllegalArgumentException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ToolChest;
import ghidra.framework.model.ToolManager;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.model.Workspace;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.CodeUnitLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class SchemeHandlerServer extends Thread {

    private int port;
    private PluginTool tool;
    private Plugin plugin;

    private boolean running;

    public SchemeHandlerServer(Plugin plugin, int port, PluginTool tool) {
        this.port = port;
        this.tool = tool;
        this.plugin = plugin;
    }

    @Override
    public void run() {
        this.running = true;
        try (ServerSocket server = new ServerSocket(this.port)) {
            // It's important to be able to exit the server cleanly, but server.accept()
            // blocks, so this causes it to release that every 50ms and check if we should exit.
            server.setSoTimeout(50);
            while (this.running) {
                try {
                    Socket client = server.accept(); // Block for a new client
                    Thread clientThread = new SchemeHandlerServerHandler(plugin, client, tool);
                    clientThread.start();
                } catch (SocketTimeoutException e) {
                }
            }
        } catch (IOException e) {
            // Most likely to occur because the port couldn't be bound, eg if multiple
            // ghidra instances are open.
            e.printStackTrace();
        }
    }

    public void cleanup() {
        this.running = false;

        // Wait for the server thread to finish (max time 50ms) before returning.
        // This ensures a new instance isn't being started before the port is freed.
        try {
            this.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Handles a single client connection to the Socket server.
     * 
     * Normally clients send a single message and disconnect, but if something
     * strange happens this in it's own thread so other clients aren't affected.
     */
    private static class SchemeHandlerServerHandler extends Thread {

        private Socket client;
        private PluginTool parentTool;
        private Plugin plugin;

        SchemeHandlerServerHandler(Plugin plugin, Socket client, PluginTool tool) {
            this.client = client;
            this.parentTool = tool;
            this.plugin = plugin;
        }

        @Override
        public void run() {
            try (BufferedReader inStream = new BufferedReader(new InputStreamReader(this.client.getInputStream()));
                    PrintWriter outStream = new PrintWriter(this.client.getOutputStream(), true);) {

                // Wait for a project to be loaded before sending the ready signal
                while (parentTool.getProject() == null) {
                    try {
                        Thread.sleep(50);
                    } catch (InterruptedException e) {
                        return;
                    }
                }

                // This line causes URI handlers that wait for the signal to send their URI
                // It doesn't especially matter what we send here.
                outStream.println("Ghidra Deep Links Handler -- Ready");
                while (true) {
                    String input = inStream.readLine();
                    if (input == null) { // Connection closed
                        break;
                    }
                    try {
                        URI uri = new URI(input);
                        handleUri(uri);
                    } catch (URISyntaxException e) {
                        // Malformed URI, just ignore that line and continue on
                        e.printStackTrace();
                    }
                }
            } catch (IOException e) {
                // Something went wrong, fall out of the loop.
            }

            try {
                client.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        /**
         * Parse a URL and jump to it's target if possible.
         * 
         * @param url The URL to attempt to handle
         */
        private void handleUri(URI uri) {
            Msg.info(SchemeHandlerServer.class, "Handling URL: " + uri.toString());

            String hash = uri.getAuthority();
            Map<String, String> query = splitQuery(uri.getRawQuery());

            if (query.get("ghidra_verify") != null) {
                Msg.showInfo(getName(), null, "Ghidra Deep Links",
                        "Ghidra Deep Links appears to be correctly installed.");
                return;
            }

            String path = query.getOrDefault("ghidra_path", "/_");
            String ref = query.getOrDefault("offset", null);

            ToolManager toolManager = parentTool.getProject().getToolManager();
            ToolChest toolChest = parentTool.getProject().getLocalToolChest();
            Workspace workspace = toolManager.getActiveWorkspace();

            PluginTool[] tools = toolManager.getRunningTools();
            PluginTool tool = null;

            DomainFile targetFile = null;
            DomainFile candidate = null;

            // Fastest path -- the file referenced in path exists and matches the hash
            try {
                candidate = parentTool.getProject().getProjectData().getFile(path);

                if (candidate != null && candidate.getMetadata().getOrDefault("Executable MD5", "").equals(hash)) {
                    Msg.debug(SchemeHandlerServer.class, "Fast-path found file.");
                    targetFile = candidate;
                }
            } catch (IllegalArgumentException e) {
                // Failure state with malformed path - e.g. non-absolute path
                // Continue with hash based lookup
            }

            // 2nd attempt -- check all open files for ones that match the hash
            if (targetFile == null) {
                List<DomainFile> matchedFiles = new ArrayList<DomainFile>();

                for (PluginTool t : tools) {
                    ProgramManager manager = t.getService(ProgramManager.class);
                    if (manager == null) { // If this tool doesn't have a ProgramManager, skip it.
                        continue;
                    }
                    for (Program p : manager.getAllOpenPrograms()) {
                        if (p.getExecutableMD5().equals(hash)) {
                            matchedFiles.add(p.getDomainFile());
                        }
                    }
                }

                if (matchedFiles.size() != 0) {
                    Msg.debug(SchemeHandlerServer.class, "Medium-path found file.");
                    targetFile = matchedFiles.get(0);
                }
            }

            // Slow path -- scan the entire project for files that match the hash
            if (targetFile == null) {
                List<DomainFile> matchedFiles = findFileByHash(hash);

                if (matchedFiles.size() == 1) {
                    Msg.debug(SchemeHandlerServer.class, "Slow-path found file.");
                    targetFile = matchedFiles.get(0); // If there's only one match, ignore the path field.
                } else {
                    for (DomainFile file : matchedFiles) {
                        if (file.getPathname().equals(path)) {
                            Msg.debug(SchemeHandlerServer.class, "Slow-path found file.");
                            targetFile = file;
                            break;
                        }
                    }
                }

                if (targetFile == null && !matchedFiles.isEmpty()) {
                    // If none of the files with the same hash have a matching filename, just choose
                    // the first one as the target
                    Msg.debug(SchemeHandlerServer.class, "Slow-path found file.");
                    targetFile = matchedFiles.get(0);
                }
            }

            if (targetFile == null) {
                // Nothing matches the hash, give up.
                Msg.showError(parentTool, null, "Failed to locate requested file!",
                        String.format("Failed to locate file with hash %s! \n Are you in the correct project?", hash));
                return;
            }

            // If no tools are open, make a new one using the first available tool
            if (tools.length == 0) {
                ToolTemplate template = toolChest.getToolTemplates()[0];
                tool = Swing.runNow(() -> workspace.runTool(template));
            } else {
                // Otherwise try to find tools that match the specified file
                for (PluginTool t : tools) {
                    ProgramManager manager = t.getService(ProgramManager.class);
                    if (manager == null) { // If this tool doesn't have a ProgramManager, skip it.
                        continue;
                    }
                    for (Program p : manager.getAllOpenPrograms()) {
                        if (p.getDomainFile().getFileID() == targetFile.getFileID()) {
                            tool = t;
                            break;
                        }
                    }
                }
                if (tool == null) {
                    tool = tools[0]; // If the requested file isn't open anywhere, choose the first tool to open it
                }
            }

            Program program = tool.getService(ProgramManager.class).openProgram(targetFile);

            scrollToLocation(tool, program, ref);

            // Attempt to bring the ghidra window to the front.
            final Window window = tool.getActiveWindow();
            Swing.runNow(() -> {
                window.toFront();
                window.requestFocus();
                window.setAlwaysOnTop(true); // Sometimes the other methods are denied / ignored by the OS
                window.setAlwaysOnTop(false); // This toggling seems to be more reliable (not 100%) in testing.
            });

        }

        private Map<String, String> splitQuery(String rawQuery) {
            Map<String, String> results = new HashMap<String, String>();

            if (rawQuery == null) {
                return results;
            }

            for (String fragment : rawQuery.split("&")) {
                String[] splitFragment = fragment.split("=");
                if (splitFragment.length == 2) {
                    String key = "";
                    String value = "";
                    try {
                        key = URLDecoder.decode(splitFragment[0], "utf-8");
                        value = URLDecoder.decode(splitFragment[1], "utf-8");
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    results.put(key, value);
                }
            }

            return results;
        }

        // Adapted from ghidra.app.plugin.core.progmgr.ProgramManagerPlugin::gotoProgramRef
        /**
         * Attempt to scroll the program listing to a specific address.
         * 
         * @param tool    The PluginTool to perform this operation in
         * @param program The current Program containing the requested location
         * @param ref     The address to jump to.
         * @return True if the operation was successful, false otherwise.
         */
        boolean scrollToLocation(PluginTool tool, Program program, String ref) {
            if (ref == null) {
                return false;
            }

            String trimmedRef = ref.trim();
            if (trimmedRef.length() == 0) {
                return false;
            }

            ProgramLocation loc = null;
            Address addr = program.getAddressFactory().getAddress(trimmedRef);
            if (addr != null && addr.isMemoryAddress()) {
                loc = new CodeUnitLocation(program, addr, 0, 0, 0);
            }
            if (loc == null) {
                Msg.showError(this, null, "Navigation Failed", "Referenced address not found: " + trimmedRef);
                return false;
            }

            tool.getService(CodeViewerService.class).goTo(loc, true);

            plugin.firePluginEvent(new ProgramLocationPluginEvent(plugin.getName(), loc, program));

            return true;
        }

        /**
         * Search the entire project for files with the specified hash.
         * 
         * @param hash The hash to search for
         * @return A list of the found files, in arbritrary order.
         */
        private List<DomainFile> findFileByHash(String hash) {
            DomainFolder rootFolder = parentTool.getProject().getProjectData().getRootFolder();
            List<DomainFile> matchedFiles = searchFolder(rootFolder, hash);

            return matchedFiles;
        }

        /**
         * Recursively search a DomainFolder for files with the specified hash.
         * 
         * @param folder The folder to search
         * @param hash   The hash to search for
         * @return A list of the found files, in arbritrary order.
         */
        private List<DomainFile> searchFolder(DomainFolder folder, String hash) {
            List<DomainFile> matchedFiles = new ArrayList<DomainFile>();
            for (DomainFile child : folder.getFiles()) {
                if (child.getMetadata().getOrDefault("Executable MD5", "").equals(hash)) {
                    matchedFiles.add(child);
                }
            }

            for (DomainFolder child : folder.getFolders()) {
                matchedFiles.addAll(searchFolder(child, hash));
            }

            return matchedFiles;
        }
    }
}
