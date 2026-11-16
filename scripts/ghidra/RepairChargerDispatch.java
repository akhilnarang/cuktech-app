// Supply switch destinations measured from bounded Thumb TBB/TBH tables.
// These are analyst annotations, not symbols supplied by the vendor.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * Sets the switch destinations that were measured from bounded Thumb TBB and TBH tables. It also
 * trims two function bodies to their measured return. The names are analyst annotations. The
 * vendor did not supply them. At the end it runs auto-analysis again.
 *
 * Arguments: none.
 *
 * Output: the destinations of each switch, in the script console.
 *
 * Program changes: function bodies and names, table listing, jump references and jump-table
 * overrides. It does not change firmware bytes.
 */
public class RepairChargerDispatch extends GhidraScript {
    // Sets the body of an existing function to [entry,end]. Does nothing if no function starts there.
    private void trim(long entry,long end) throws Exception {
        Function f=getFunctionAt(toAddr(entry));
        if(f!=null)f.setBody(new AddressSet(toAddr(entry),toAddr(end)));
    }
    // Replaces the jump references of one TBB (width 1) or TBH (width 2) switch with the table destinations.
    private void table(long entry,long branch,long start,int count,int width,String name) throws Exception {
        Function f=getFunctionAt(toAddr(entry));
        if(f==null){disassemble(toAddr(entry));f=createFunction(toAddr(entry),name);}
        if(f==null)throw new IllegalStateException("Cannot establish function at "+Long.toHexString(entry));
        f.setName(name,SourceType.USER_DEFINED);
        Instruction instruction=getInstructionAt(toAddr(branch));
        if(instruction==null)throw new IllegalStateException("Missing switch instruction");
        for(Reference reference:instruction.getReferencesFrom())
            if(reference.getReferenceType().isJump())currentProgram.getReferenceManager().delete(reference);
        clearListing(toAddr(start),toAddr(start+count*width-1));
        ArrayList<Address> targets=new ArrayList<>();
        for(int index=0;index<count;index++) {
            long relative=width==1?Byte.toUnsignedInt(getByte(toAddr(start+index))):Short.toUnsignedInt(getShort(toAddr(start+index*2)));
            Address target=toAddr(start+2*relative);
            targets.add(target);disassemble(target);
            instruction.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
        }
        new JumpTable(toAddr(branch),targets,true,0).writeOverride(f);
        CreateFunctionCmd.fixupFunctionBody(currentProgram,f,monitor);
        println("CUKTECH fixed "+name+" switch "+Long.toHexString(branch)+": "+targets);
    }
    public void run() throws Exception {
        // The original automatic string decoder switch lacked an inferred bound
        // and pulled unrelated code into its body; limit it to its measured return.
        trim(0x40e850L,0x40e88dL);
        trim(0x41d1a0L,0x41d1d1L);
        table(0x40e850L,0x40e85cL,0x40e860L,4,1,"ui_decode_encoded_character");
        table(0x41b3f0L,0x41b3feL,0x41b402L,8,2,"dfu_worker_state_machine");
        table(0x41cd54L,0x41cd68L,0x41cd6cL,7,1,"uart_command_group1");
        table(0x41cd54L,0x41cd9eL,0x41cda2L,7,1,"uart_command_group1");
        table(0x417868L,0x41789cL,0x4178a0L,5,1,"simple_profile_write_handler");
        analyzeAll(currentProgram);
    }
}
