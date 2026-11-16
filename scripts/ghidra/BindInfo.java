// For each hex addr: print nearest function at/before it, and callers (xrefs) of that function. Read-only.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;

/**
 * For each address, prints the function that contains it, or the nearest function before it.
 * It also prints each reference to the entry of that function and the caller function.
 *
 * Arguments:
 * <ol>
 * <li>output file: path of a text file. The script overwrites it. Example: {@code /tmp/out.txt}</li>
 * <li>address 1..n: hex address. Example: {@code 0040faec}</li>
 * </ol>
 *
 * Program changes: none.
 */
public class BindInfo extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(a[0]));
        for (int i = 1; i < a.length; i++) {
            Address ad = toAddr(a[i]);
            Function f = getFunctionContaining(ad);
            if (f == null) f = getFunctionBefore(ad);
            out.println("== " + a[i] + " -> " + (f == null ? "none" : f.getName() + " @ " + f.getEntryPoint() + " body " + f.getBody().getMinAddress() + "-" + f.getBody().getMaxAddress()));
            if (f == null) continue;
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                Function c = getFunctionContaining(r.getFromAddress());
                out.println("   caller " + r.getFromAddress() + " " + r.getReferenceType() + " in " + (c == null ? "?" : c.getName()));
            }
        }
        out.close();
    }
}
