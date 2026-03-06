package deeplinks;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class DeepLinksUtil {
    public static  String getAddressText(Address address) {
        return "0x" + address.toString();
    }

    public static String buildURL(Address address, Program prog) {
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
}
