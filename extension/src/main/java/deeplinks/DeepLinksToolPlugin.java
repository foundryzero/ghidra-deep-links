package deeplinks;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import org.apache.commons.text.StringEscapeUtils;

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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * A plugin that provides actions for copying disas :// deep links to the
 * current address or symbol in a code or decompiler listing.
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
    abstract class LinkCreateAction extends DockingAction {
        /*
         * Encapsulation of context menu actions for copying a link to the current
         * location to the clipboard Subclasses of this should override the
         * makeClipboardString abstract method to specify the exact text
         */

        public LinkCreateAction(String name, String owner) {
            /*
             * name will be the title of this action in the context menu.
             */
            super(name, owner);
        }

        @Override
        public boolean isAddToPopup(ActionContext context) {
            // This context menu only makes sense inside a Listing or Decompiler window.
            return (context instanceof ListingActionContext || context instanceof DecompilerActionContext);
        }

        @Override
        public void actionPerformed(ActionContext context) {
            /*
             * Copy a link to the clipboard, using makeClipboardString to get the exact link
             * text.
             */
            if (!(context instanceof ListingActionContext || context instanceof DecompilerActionContext)) {
                return;
            }

            NavigatableActionContext naviContext = (NavigatableActionContext) context;

            String clipboardData = makeClipboardString(naviContext.getLocation().getAddress(),
                    naviContext.getProgram());
            copyToSystemClipboard(clipboardData);
        }

        public void addToTool(PluginTool targetTool) {
            /*
             * Add this action to the context menu for the given PluginTool
             */
            setPopupMenuData(new MenuData(new String[] { this.getName() }));
            setEnabled(true);
            targetTool.addAction(this);
        }

        /*
         * Subclasses should override this method to specify the text to copy to the
         * clipboard when this action is performed on the given address.
         */
        protected abstract String makeClipboardString(Address address, Program prog);

        protected String getAddressText(Address address) {
            return "0x" + address.toString();
        }

        protected String getSymbolText(Address address, Program prog) {
            SymbolTable symbols = prog.getSymbolTable();
            Symbol symbol = symbols.getPrimarySymbol(address);
            if (symbol != null) {
                return symbol.getName();
            }
            return getAddressText(address);
        }

        protected String buildURL(Address address, Program prog) {
            SymbolTable symbols = prog.getSymbolTable();
            Symbol symbol = symbols.getPrimarySymbol(address);
            String loc = getAddressText(address);
            try {
                // Don't encode slashes inside the query string
                // This is explicitly allowed in RFC-3986
                // see https://datatracker.ietf.org/doc/html/rfc3986#section-3.4
                String encodedPath = URLEncoder.encode(prog.getDomainFile().getPathname(), "utf-8");
                encodedPath = encodedPath.replace("%2F", "/");

                if (symbol != null) {
                    final String symbolName = symbol.getName(true);
                    final String TEMPLATE = "disas://%s/?ghidra_path=%s&offset=%s&label=%s";
                    return TEMPLATE.formatted(prog.getExecutableMD5(), encodedPath, URLEncoder.encode(loc, "utf-8"),
                            URLEncoder.encode(symbolName, "utf-8"));
                } else {
                    final String TEMPLATE = "disas://%s/?ghidra_path=%s&offset=%s";
                    return TEMPLATE.formatted(prog.getExecutableMD5(), encodedPath, URLEncoder.encode(loc, "utf-8"));
                }
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return "";
        }

        private static void copyToSystemClipboard(String data) {
            Clipboard systemClip = GClipboard.getSystemClipboard();
            systemClip.setContents(new StringSelection(data), null);
        }
    }

    public DeepLinksToolPlugin(PluginTool tool) {
        super(tool);
        registerActions();
    }

    private void registerActions() {
        /*
         * Create and register the different type of link copying actions.
         */
        new LinkCreateAction("Copy Deep Link", getName()) {
            // Just the URL

            @Override
            protected String makeClipboardString(Address address, Program prog) {
                return buildURL(address, prog);
            }

        }.addToTool(tool);

        new LinkCreateAction("Copy Markdown Deep Link", getName()) {
            // Markdown formatted link

            @Override
            protected String makeClipboardString(Address address, Program prog) {
                String url = buildURL(address, prog);
                String linkTitle = getSymbolText(address, prog);
                return String.format("[`%s`](%s)", linkTitle, url);
            }

        }.addToTool(tool);

        new LinkCreateAction("Copy draw.io Deep Link", getName()) {
            private final static String template = "<mxGraphModel><root><mxCell id=\"0\"/><mxCell id=\"1\" parent=\"0\"/><UserObject label=\"&lt;a href=&quot;%s&quot;&gt;%s&lt;/a&gt;\" link=\"%s\" id=\"2\"><mxCell style=\"rounded=1;whiteSpace=wrap;html=1;\" vertex=\"1\" parent=\"1\"><mxGeometry width=\"120\" height=\"60\" as=\"geometry\"/></mxCell></UserObject></root></mxGraphModel>";

            @Override
            protected String makeClipboardString(Address address, Program prog) {
                String url = StringEscapeUtils.escapeHtml4(buildURL(address, prog));
                String linkTitle = StringEscapeUtils.escapeHtml4(getSymbolText(address, prog));
                return String.format(template, url, linkTitle, url);
            }
        }.addToTool(tool);

    }

}
