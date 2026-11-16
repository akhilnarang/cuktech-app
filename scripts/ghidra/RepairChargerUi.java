// Correct measured UI function boundaries and Thumb switch tables for 0073.
// Analyst annotations only: original image bytes are never changed.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * Sets the measured UI function boundaries and the Thumb TBB switch tables for the 0073 image.
 * These are analyst annotations.
 *
 * Arguments: none.
 *
 * Output: the destinations of each switch, in the script console.
 *
 * Program changes: function bodies and names, table listing, jump references and jump-table
 * overrides. It does not change firmware bytes.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1.
 */
public class RepairChargerUi extends GhidraScript {
    // Creates the function if necessary and sets its body to [entry,end] and its name.
    private void bounded(long entry,long end,String name) throws Exception {
        Function f=getFunctionAt(toAddr(entry));
        if(f==null) {
            disassemble(toAddr(entry));
            f=createFunction(toAddr(entry),name);
        }
        if(f==null)throw new IllegalStateException("Cannot establish UI function "+Long.toHexString(entry));
        f.setBody(new AddressSet(toAddr(entry),toAddr(end)));
        f.setName(name,SourceType.USER_DEFINED);
    }
    // Replaces the jump references of one Thumb TBB switch with the destinations read from its byte table.
    private void table(long entry,long branch,long start,int count,String name) throws Exception {
        Function f=getFunctionAt(toAddr(entry));
        if(f==null)throw new IllegalStateException("Missing function "+Long.toHexString(entry));
        Instruction ins=getInstructionAt(toAddr(branch));
        if(ins==null||!ins.getMnemonicString().equalsIgnoreCase("tbb"))
            throw new IllegalStateException("Missing measured TBB at "+Long.toHexString(branch));
        for(Reference r:ins.getReferencesFrom())
            if(r.getReferenceType().isJump())currentProgram.getReferenceManager().delete(r);
        clearListing(toAddr(start),toAddr(start+count-1));
        ArrayList<Address> targets=new ArrayList<>();
        for(int i=0;i<count;i++) {
            Address target=toAddr(start+2*Byte.toUnsignedInt(getByte(toAddr(start+i))));
            targets.add(target);disassemble(target);
            ins.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
        }
        new JumpTable(toAddr(branch),targets,true,0).writeOverride(f);
        println("CUKTECH UI "+name+" "+Long.toHexString(branch)+": "+targets);
    }
    public void run() throws Exception {
        if(!"65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1".equals(currentProgram.getExecutableSHA256()))
            throw new IllegalArgumentException("UI annotations require the measured AD1204 0073 raw image.");
        // Separate tail-branch wrappers before creating their actual targets.
        bounded(0x41f7acL,0x41f7b3L,"ui_select_screen_wrapper");
        bounded(0x4065a8L,0x4065c1L,"ui_main_screen_input");
        bounded(0x410130L,0x4101f1L,"ui_main_page_initialize");
        bounded(0x406560L,0x40659dL,"ui_cycle_main_page");
        bounded(0x40faecL,0x40fc45L,"ui_select_screen");
        table(0x40faecL,0x40fb10L,0x40fb14L,14,"leave_screen_1_to_14");
        table(0x40faecL,0x40fb68L,0x40fb6cL,14,"enter_screen_1_to_14");
        table(0x41113cL,0x411174L,0x411178L,5,"main_page_0_to_4");
        CreateFunctionCmd.fixupFunctionBody(currentProgram,getFunctionAt(toAddr(0x40faecL)),monitor);
        CreateFunctionCmd.fixupFunctionBody(currentProgram,getFunctionAt(toAddr(0x41113cL)),monitor);
        println("CUKTECH UI measured boundaries/switches annotated; no firmware bytes patched.");
    }
}
