// Decompile the function containing each given address, then (depth 1) its
// callees. args: <out file> <depth> <hex addr> [hex addr ...]. Can create functions.
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

/**
 * Decompiles the function that contains each address. Then it decompiles the called functions,
 * down to the given depth. Each function is written once. The decompiler timeout is 60 s.
 *
 * Arguments:
 * <ol>
 * <li>output file: path of a text file. The script overwrites it. Example: {@code /tmp/out.txt}</li>
 * <li>depth: decimal call depth. 0 decompiles only the given functions. Example: {@code 1}</li>
 * <li>address 1..n: hex address. Example: {@code 0040faec}</li>
 * </ol>
 *
 * Program changes: if no function contains an address, it disassembles Thumb code there and
 * creates a function. Run it with {@code -readOnly} to discard these changes.
 */
public class DecompileAt extends GhidraScript {
    private DecompInterface dec;
    private PrintWriter out;
    private final Set<Function> done = new HashSet<>();

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        out = new PrintWriter(new FileWriter(a[0]));
        int depth = Integer.parseInt(a[1]);
        dec = new DecompInterface();
        dec.openProgram(currentProgram);
        for (int i = 2; i < a.length; i++) {
            Address ad = toAddr(a[i]);
            Function f = getFunctionContaining(ad);
            if (f == null) {  // Cortex-M: Thumb only
                new ArmDisassembleCommand(ad, null, true).applyTo(currentProgram, monitor);
                createFunction(ad, null);
                f = getFunctionContaining(ad);
            }
            if (f == null) { out.println("// no function contains " + a[i]); continue; }
            walk(f, depth);
        }
        out.close();
    }

    private void walk(Function f, int depth) {
        if (!done.add(f)) return;
        out.println("################ " + f.getName() + " @ " + f.getEntryPoint()
                + "  size " + f.getBody().getNumAddresses());
        DecompileResults r = dec.decompileFunction(f, 60, monitor);
        out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed");
        if (depth > 0) for (Function c : f.getCalledFunctions(monitor)) walk(c, depth - 1);
    }
}
