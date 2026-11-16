// Decompile every function that references a string matching a search term,
// plus its direct callers and callees (one level). Read-only analysis.
// args: <out file> <term1> [term2 ...]
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

/**
 * Finds each defined string that contains a search term (case is ignored). For each function that
 * references such a string, it prints the strings, the callers, the callees and the pseudocode.
 * The decompiler timeout is 60 s.
 *
 * Arguments:
 * <ol>
 * <li>output file: path of a text file. The script overwrites it. Example: {@code /tmp/out.txt}</li>
 * <li>term 1..n: text to find in strings. Example: {@code ota}</li>
 * </ol>
 *
 * Program changes: none.
 */
public class DumpByStrings extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(a[0]));
        List<String> terms = Arrays.asList(a).subList(1, a.length);
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        Map<Function, Set<String>> hits = new LinkedHashMap<>();
        for (Data d : listing.getDefinedData(true)) {
            StringDataInstance s = StringDataInstance.getStringDataInstance(d);
            if (s == null || s == StringDataInstance.NULL_INSTANCE) continue;
            String v = s.getStringValue();
            if (v == null) continue;
            for (String t : terms) {
                if (!v.toLowerCase().contains(t.toLowerCase())) continue;
                for (Reference r : getReferencesTo(d.getAddress())) {
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    if (f != null) hits.computeIfAbsent(f, k -> new TreeSet<>()).add(v.trim());
                }
            }
        }
        Set<Function> done = new HashSet<>();
        for (Map.Entry<Function, Set<String>> e : hits.entrySet()) {
            Function f = e.getKey();
            out.println("################ " + f.getName() + " @ " + f.getEntryPoint());
            out.println("strings: " + e.getValue());
            out.println("callers: " + names(f.getCallingFunctions(monitor)));
            out.println("callees: " + names(f.getCalledFunctions(monitor)));
            emit(out, dec, f, done);
        }
        out.close();
        println("functions with hits: " + hits.size());
    }

    private String names(Set<Function> fs) {
        List<String> n = new ArrayList<>();
        for (Function f : fs) n.add(f.getName() + "@" + f.getEntryPoint());
        return n.toString();
    }

    private void emit(PrintWriter out, DecompInterface dec, Function f, Set<Function> done) {
        if (!done.add(f)) { out.println("(already decompiled above)\n"); return; }
        DecompileResults r = dec.decompileFunction(f, 60, monitor);
        out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed");
        out.println();
    }
}
