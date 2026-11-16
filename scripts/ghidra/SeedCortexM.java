// Pre-analysis for a raw Cortex-M image: seed functions from the vector
// table (Thumb entry points) and enable the aggressive instruction finder.
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

/**
 * Pre-analysis script for a raw Cortex-M image. It reads vector table entries 1 to 127 from the
 * lowest memory address. Entry 0 is the initial stack pointer. Each odd entry inside the image is
 * a Thumb entry point: the script disassembles it and creates a function. It also enables the
 * analysis option "ARM Aggressive Instruction Finder".
 *
 * Arguments: none.
 *
 * Output: the number of seeded entries, in the script console.
 *
 * Program changes: it disassembles code, creates functions and sets one analysis option.
 */
public class SeedCortexM extends GhidraScript {
    @Override
    public void run() throws Exception {
        setAnalysisOption(currentProgram, "ARM Aggressive Instruction Finder", "true");
        Memory mem = currentProgram.getMemory();
        Address base = mem.getMinAddress();
        long lo = base.getOffset(), hi = mem.getMaxAddress().getOffset();
        int seeded = 0;
        for (int i = 1; i < 128; i++) {  // entry 0 is the initial stack pointer
            long v = mem.getInt(base.add(4L * i)) & 0xffffffffL;
            if ((v & 1) == 0 || v - 1 < lo || v - 1 > hi) continue;
            Address ep = base.getNewAddress(v - 1);
            new ArmDisassembleCommand(ep, null, true).applyTo(currentProgram, monitor);
            if (getFunctionAt(ep) == null) createFunction(ep, null);
            seeded++;
        }
        println("seeded vector entries: " + seeded);
    }
}
