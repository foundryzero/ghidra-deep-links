package deeplinks;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Provides a plugin to catch disas:// deep links sent across a socket and
 * attempt to find open the files they point to.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = UtilityPluginPackage.NAME,
    category = PluginCategoryNames.NAVIGATION,
    shortDescription = "Handles incoming disas:// deep links.",
    description = "Handles incoming disas:// deep links.",
    // The services required actually are inside the subtools, not the main ghidra window itself, so we can't declare them as required here.
    servicesRequired = { }, 
    eventsProduced = { }
)
//@formatter:on
public class DeepLinksPlugin extends Plugin implements ApplicationLevelOnlyPlugin {

    static final int PORT = 5740; // IANA unassigned as of 2023-07-28

    ProgramManager programManager;
    SchemeHandlerServer serverThread;

    /**
     * Constructs a new instance of the plugin. Called very early on in the
     * initialisation process.
     * 
     * @param tool The tool that the plugin is being loaded into.
     */
    public DeepLinksPlugin(PluginTool tool) {
        super(tool);

        // Create a thread to run our socket server on
        serverThread = new SchemeHandlerServer(this, PORT, tool);

    }

    /**
     * Start the server.
     * 
     * Called when the plugin loader decides it's time to load our plugin.
     */
    @Override
    public void init() {
        super.init();

        serverThread.start();
    }

    /**
     * Stop and cleanup the server.
     * 
     * Called when the plugin gets unloaded.
     */
    @Override
    public void dispose() {
        serverThread.cleanup();
    }

}
