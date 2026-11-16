// args: <out> <start hex> <end hex> [refaddr hex ...]  Disassembles (Thumb) and dumps listing; lists refs to given addrs. Read-only output.
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;

/**
 * Prints the instructions in an address range. Then, for each reference address, prints each
 * reference to it and the function that contains the reference. The end address is inclusive.
 *
 * Arguments:
 * <ol>
 * <li>output file: path of a text file. The script overwrites it. Example: {@code /tmp/out.txt}</li>
 * <li>start: hex address. Example: {@code 0041b3f0}</li>
 * <li>end: hex address, inclusive. Example: {@code 0041b500}</li>
 * <li>reference address 1..n (optional): hex address. Example: {@code 2000cf28}</li>
 * </ol>
 *
 * Program changes: if there is no instruction at the start address, it disassembles Thumb code
 * from there. Run it with {@code -readOnly} to discard this change.
 */
public class StateListing extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(a[0]));
        Address s = toAddr(a[1]), e = toAddr(a[2]);
        if (getInstructionAt(s) == null) new ArmDisassembleCommand(s, null, true).applyTo(currentProgram, monitor);
        for (Instruction i : currentProgram.getListing().getInstructions(new AddressSet(s, e), true))
            out.println(i.getAddress() + "  " + i);
        for (int k = 3; k < a.length; k++) {
            out.println("== refs to " + a[k]);
            for (Reference r : getReferencesTo(toAddr(a[k]))) {
                Function f = getFunctionContaining(r.getFromAddress());
                out.println(r.getFromAddress() + " " + r.getReferenceType() + " in " + (f == null ? "?" : f.getName()));
            }
        }
        out.close();
    }
}
