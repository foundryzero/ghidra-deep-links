package deeplinks;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.dnd.GClipboard;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;


/**
 * A plugin that provides actions for copying disas :// deep links to the current
 * address or symbol in a code or decompiler listing.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = UtilityPluginPackage.NAME,
    category = PluginCategoryNames.NAVIGATION,
    shortDescription = "Provides actions for creating deep links in code listings.",
    description = "Provides actions for creating deep links in code listings.",
    servicesRequired = { },
    eventsProduced = { }
)
//@formatter:on
public class DeepLinksToolPlugin extends ProgramPlugin {

    public DeepLinksToolPlugin(PluginTool tool) {
        super(tool);

        registerActions();
    }

    private void registerActions() {
        // Copy link only action
        DockingAction copyLinkToAddressAction = new DockingAction("Copy Deep Link", getName()) {
            @Override
            public boolean isAddToPopup(ActionContext context) {
                // This context menu only makes sense inside a Listing or Decompiler window.
                return (context instanceof ListingActionContext || context instanceof DecompilerActionContext);
            }

            @Override
            public void actionPerformed(ActionContext context) {
                if (!(context instanceof ListingActionContext || context instanceof DecompilerActionContext)) {
                    return;
                }

                NavigatableActionContext naviContext = (NavigatableActionContext) context;
                Program prog = naviContext.getProgram();
                ProgramLocation loc = naviContext.getLocation();

                SymbolTable symbols = prog.getSymbolTable();
                Symbol symbol = symbols.getPrimarySymbol(loc.getAddress());

                String url = buildURL("0x" + loc.getAddress().toString(), prog, symbol);
                copyToSystemClipboard(url);
            }
        };

        // Adds the action to the right-click menu, and enables it.
        copyLinkToAddressAction.setPopupMenuData(new MenuData(new String[] { "Copy Deep Link" }));
        copyLinkToAddressAction.setEnabled(true);
        tool.addAction(copyLinkToAddressAction);

        DockingAction copyMarkdownLinkToAddressAction = new DockingAction("Copy Markdown Deep Link", getName()) {
            @Override
            public boolean isAddToPopup(ActionContext context) {
                // This context menu only makes sense inside a Listing or Decompiler window.
                return (context instanceof ListingActionContext || context instanceof DecompilerActionContext);
            }

            @Override
            public void actionPerformed(ActionContext context) {
                if (!(context instanceof ListingActionContext || context instanceof DecompilerActionContext)) {
                    return;
                }

                NavigatableActionContext naviContext = (NavigatableActionContext) context;
                Program prog = naviContext.getProgram();
                ProgramLocation loc = naviContext.getLocation();

                SymbolTable symbols = prog.getSymbolTable();
                Symbol symbol = symbols.getPrimarySymbol(loc.getAddress());

                String addressText = "0x" + loc.getAddress().toString();
                String url = buildURL(addressText, prog, symbol);
                String linkTitle = addressText;
                if (symbol != null) {
                    linkTitle = symbol.getName();
                }
                String markdown = String.format("[`%s`](%s)", linkTitle, url);
                copyToSystemClipboard(markdown);
            }
        };

        // Adds the action to the right-click menu, and enables it.
        copyMarkdownLinkToAddressAction.setPopupMenuData(new MenuData(new String[] { "Copy Markdown Deep Link" }));
        copyMarkdownLinkToAddressAction.setEnabled(true);
        tool.addAction(copyMarkdownLinkToAddressAction);
    }

    private String buildURL(String loc, Program program, Symbol symbol) {
        try {
            // Don't encode slashes inside the query string
            // This is explicitly allowed in RFC-3986
            // see https://datatracker.ietf.org/doc/html/rfc3986#section-3.4
            String encodedPath = URLEncoder.encode(program.getDomainFile().getPathname(), "utf-8");
            encodedPath = encodedPath.replace("%2F", "/");

            if (symbol != null) {
                final String symbolName = symbol.getName(true);
                final String TEMPLATE = "disas://%s/?ghidra_path=%s&offset=%s&label=%s";
                return TEMPLATE.formatted(program.getExecutableMD5(), encodedPath, URLEncoder.encode(loc, "utf-8"), URLEncoder.encode(symbolName, "utf-8"));
            } else {
                final String TEMPLATE = "disas://%s/?ghidra_path=%s&offset=%s";
                return TEMPLATE.formatted(program.getExecutableMD5(), encodedPath, URLEncoder.encode(loc, "utf-8"));
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }

    private void copyToSystemClipboard(String data) {
        Clipboard systemClip = GClipboard.getSystemClipboard();
        systemClip.setContents(new StringSelection(data), null);
    }
}
