// For each 32-bit value arg: find literal-pool words equal to it, print code refs (addr + function). Read-only.
// args: <out file> <hex value> [...]
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.*;

/**
 * For each 32-bit value, finds each little-endian word in memory that is equal to it. For each
 * match, it prints the code references to that literal-pool word and their functions.
 *
 * Arguments:
 * <ol>
 * <li>output file: path of a text file. The script overwrites it. Example: {@code /tmp/out.txt}</li>
 * <li>value 1..n: hex 32-bit value, without {@code 0x}. Example: {@code 20001730}</li>
 * </ol>
 *
 * Program changes: none.
 */
public class EcdsaXrefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(a[0]));
        for (int i = 1; i < a.length; i++) {
            long v = Long.parseLong(a[i], 16);
            byte[] pat = {(byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24)};
            out.println("== value " + a[i]);
            Address s = currentProgram.getMinAddress();
            while (s != null) {
                Address hit = currentProgram.getMemory().findBytes(s, pat, null, true, monitor);
                if (hit == null) break;
                out.print("  pool " + hit + ":");
                for (Reference r : getReferencesTo(hit)) {
                    Function f = getFunctionContaining(r.getFromAddress());
                    out.print(" " + r.getFromAddress() + "(" + (f == null ? "?" : f.getName()) + ")");
                }
                out.println();
                s = hit.add(1);
            }
        }
        out.close();
    }
}
