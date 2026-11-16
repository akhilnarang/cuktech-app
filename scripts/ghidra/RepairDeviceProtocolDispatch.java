// AD1204 0073: repair measured protocol/scene switch destinations and export focused evidence.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import com.google.gson.Gson;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Sets the measured TBB destinations of the protocol and scene switches. Then it decompiles each
 * function with an entry in 0x00406b78..0x00409fc0 or 0x00414c70..0x00415b80 and writes one JSON
 * row for each function. The decompiler timeout is 30 s.
 *
 * Arguments:
 * <ol>
 * <li>output file: new path of a JSON Lines file. The script creates the parent directories.
 * Example: {@code artifacts/firmware/reproduced-0073/analysis/protocol-dispatch.jsonl}</li>
 * </ol>
 *
 * Output: one row for each function, with address, body, pseudocode and decompiler error.
 *
 * Program changes: table listing, jump references, jump-table overrides and function bodies.
 * It does not change firmware bytes. The changes stay in the project if you do not use
 * {@code -readOnly}.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output file already exists. The switch repairs
 * are already applied at that point.
 */
public class RepairDeviceProtocolDispatch extends GhidraScript {
    // Replaces the jump references of one Thumb TBB switch with the destinations read from its byte table.
    private void table(long entry,long branch,int count) throws Exception {
        Function f=getFunctionAt(toAddr(entry));
        if(f==null) throw new IllegalStateException("Missing function "+Long.toHexString(entry));
        Instruction ins=getInstructionAt(toAddr(branch));
        if(ins==null || !ins.getMnemonicString().equalsIgnoreCase("tbb"))
            throw new IllegalStateException("Expected TBB at "+Long.toHexString(branch));
        long start=branch+4;
        for(Reference r:ins.getReferencesFrom())
            if(r.getReferenceType().isJump())currentProgram.getReferenceManager().delete(r);
        clearListing(toAddr(start),toAddr(start+count-1));
        ArrayList<Address> targets=new ArrayList<>();
        for(int i=0;i<count;i++) {
            Address target=toAddr(start+2*Byte.toUnsignedInt(getByte(toAddr(start+i))));
            targets.add(target); disassemble(target);
            ins.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
        }
        new JumpTable(toAddr(branch),targets,true,0).writeOverride(f);
        CreateFunctionCmd.fixupFunctionBody(currentProgram,f,monitor);
        println("CUKTECH protocol switch "+Long.toHexString(branch)+": "+targets);
    }
    public void run() throws Exception {
        if(!"65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1".equals(currentProgram.getExecutableSHA256()))
            throw new IllegalArgumentException("Protocol annotations require the measured AD1204 0073 raw image.");
        // Bounds are explicit CMP/BHI immediately preceding each switch, or
        // the shared helper at 0x4054b6 / 0x405580: count minus one <= 3.
        table(0x409784L,0x409800L,8);
        table(0x406e30L,0x406efeL,4);
        table(0x406e30L,0x406f16L,4);
        table(0x406e30L,0x406f5eL,4);
        long[][] scenes={{0x407104L,0x407112L},{0x407508L,0x407514L},
            {0x407750L,0x40775cL},{0x4079d0L,0x4079daL},{0x407af8L,0x407b02L},
            {0x407bf4L,0x407bfeL},{0x407d1cL,0x407d26L},{0x407e70L,0x407e7eL},
            {0x407fbcL,0x407fc8L},{0x408180L,0x40818aL},{0x408298L,0x4082a2L},
            {0x4083a0L,0x4083aaL}};
        for(long[] s:scenes)table(s[0],s[1],4);
        Path out=Paths.get(getScriptArgs()[0]);
        if(Files.exists(out))throw new IllegalArgumentException("Output file must be new");
        Files.createDirectories(out.getParent());
        DecompInterface decompiler=new DecompInterface();decompiler.openProgram(currentProgram);
        Gson json=new Gson();
        try(java.io.BufferedWriter writer=Files.newBufferedWriter(out,StandardCharsets.UTF_8)) {
            FunctionIterator functions=currentProgram.getFunctionManager().getFunctions(true);
            while(functions.hasNext()) {
                Function f=functions.next();long a=f.getEntryPoint().getOffset();
                if(!((a>=0x406b78L&&a<=0x409fc0L)||(a>=0x414c70L&&a<=0x415b80L)))continue;
                DecompileResults d=decompiler.decompileFunction(f,30,monitor);
                Map<String,Object> row=new LinkedHashMap<>();row.put("address",f.getEntryPoint().toString());
                row.put("body",f.getBody().toString());row.put("error",d.getErrorMessage());
                row.put("decompiled",d.decompileCompleted()?d.getDecompiledFunction().getC():null);
                writer.write(json.toJson(row));writer.newLine();
            }
        }finally{decompiler.dispose();}
        println("CUKTECH focused protocol export: "+out);
    }
}
