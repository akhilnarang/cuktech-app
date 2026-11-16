// Print disassembly of the functions containing each address. args: <out file> <hex addr> [...]. Read-only.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.io.*;

/**
 * Prints the disassembly of the function that contains each address.
 *
 * Arguments:
 * <ol>
 * <li>output file: path of a text file. The script overwrites it. Example: {@code /tmp/out.txt}</li>
 * <li>address 1..n: hex address. Example: {@code 0040faec}</li>
 * </ol>
 *
 * Program changes: none.
 */
public class EcdsaListing extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(a[0]));
        for (int i = 1; i < a.length; i++) {
            Function f = getFunctionContaining(toAddr(a[i]));
            if (f == null) { out.println("// no function at " + a[i]); continue; }
            out.println("######## " + f.getName());
            for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true))
                out.println(ins.getAddress() + "  " + ins);
        }
        out.close();
    }
}
