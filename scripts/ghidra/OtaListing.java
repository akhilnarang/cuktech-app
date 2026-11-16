// Disassemble (Thumb) and print instructions in [start,end). args: <out> <start hex> <end hex>
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;
/**
 * Disassembles the range as Thumb code and prints each instruction. The end address is exclusive.
 *
 * Arguments:
 * <ol>
 * <li>output file: path of a text file. The script overwrites it. Example: {@code /tmp/out.txt}</li>
 * <li>start: hex address, inclusive. Example: {@code 0041b3f0}</li>
 * <li>end: hex address, exclusive. Example: {@code 0041b500}</li>
 * </ol>
 *
 * Program changes: it disassembles the range. Run it with {@code -readOnly} to discard this change.
 */
public class OtaListing extends GhidraScript {
    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(a[0]));
        Address s = toAddr(a[1]), e = toAddr(a[2]);
        new ArmDisassembleCommand(new AddressSet(s, e.subtract(1)), null, true).applyTo(currentProgram, monitor);
        for (Instruction i : currentProgram.getListing().getInstructions(new AddressSet(s, e.subtract(1)), true))
            out.println(i.getAddress() + "  " + i);
        out.close();
    }
}
