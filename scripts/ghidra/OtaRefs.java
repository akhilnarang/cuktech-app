// Read-only: for each hex addr arg, list references to it (and addr|1) with containing function;
// also list instructions whose scalar operands equal any value given as "s:<hex>".
// args: <out file> <hexaddr|s:hexval>...
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import java.io.*;
import java.util.*;

/**
 * For each address, prints each reference to the address and to the address with bit 0 set
 * (Thumb pointer), with the function that contains the reference. For each {@code s:} value,
 * prints each instruction that has a scalar operand equal to that value.
 *
 * Arguments:
 * <ol>
 * <li>output file: path of a text file. The script overwrites it. Example: {@code /tmp/out.txt}</li>
 * <li>item 1..n: hex address, or {@code s:} and a hex scalar value.
 * Examples: {@code 0041b3f0}, {@code s:aec8}</li>
 * </ol>
 *
 * Program changes: none.
 */
public class OtaRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(a[0]));
        Set<Long> vals = new HashSet<>();
        for (int i = 1; i < a.length; i++) {
            if (a[i].startsWith("s:")) { vals.add(Long.parseLong(a[i].substring(2), 16)); continue; }
            long v = Long.parseLong(a[i], 16);
            for (long x : new long[]{v, v | 1}) {
                for (Reference r : getReferencesTo(toAddr(x))) {
                    Function f = getFunctionContaining(r.getFromAddress());
                    out.println(String.format("%x <- %s %s fn=%s", x, r.getFromAddress(), r.getReferenceType(),
                        f == null ? "-" : f.getName() + "@" + f.getEntryPoint()));
                }
            }
        }
        if (!vals.isEmpty()) for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
            for (int op = 0; op < ins.getNumOperands(); op++) for (Object o : ins.getOpObjects(op))
                if (o instanceof Scalar && vals.contains(((Scalar) o).getUnsignedValue())) {
                    Function f = getFunctionContaining(ins.getAddress());
                    out.println(String.format("scalar %x at %s '%s' fn=%s", ((Scalar) o).getUnsignedValue(), ins.getAddress(), ins,
                        f == null ? "-" : f.getName() + "@" + f.getEntryPoint()));
                }
        }
        out.close();
    }
}
