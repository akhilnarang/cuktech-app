// AD1204 0073 allocation policy. Analyst annotations in a read-only project.
// Argument: new output directory. No device or peripheral execution.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.google.gson.Gson;

/**
 * Exports static evidence for the AD1204 0073 port allocation policy. It repairs the scene-dispatch
 * and cap-clamp TBB switches and exports the selected allocation and helper functions.
 * The RAM table comes from the reconstructed startup data.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-allocation}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code functions.jsonl}: one row for each requested exact function entry, with body and pseudocode.</li>
 * <li>{@code instructions.jsonl}: the original instruction records and bytes.</li>
 * <li>{@code analysis.json}: image hash, counts and the scope of the evidence.</li>
 * </ul>
 *
 * Program changes: it sets exact function bodies, clears and disassembles
 * measured switch tables and adds jump references. It does not change firmware bytes.
 * Run it with {@code -readOnly} on a project copy, so that Ghidra discards these changes.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output directory already exists.
 */
public class AuditAllocation extends GhidraScript {
    // Gives the function at start exactly [start,end] as its body. Removes that range from an
    // enclosing function that has a different entry.
    private void bounded(long start,long end,String name) throws Exception {
        Address entry=toAddr(start);AddressSet range=new AddressSet(entry,toAddr(end));Function old=getFunctionContaining(entry);
        if(old!=null&&!old.getEntryPoint().equals(entry)){AddressSet keep=new AddressSet(old.getBody());keep.delete(range);old.setBody(keep);}
        Function f=getFunctionAt(entry);if(f==null){new ArmDisassembleCommand(entry,null,true).applyTo(currentProgram,monitor);f=createFunction(entry,name);}
        if(f==null)throw new IllegalStateException("Missing entry "+entry);f.setBody(range);
    }
    // Replaces the jump references of one Thumb TBB switch with the destinations read from its byte table.
    private void table(long entry,long branch,int count) throws Exception {
        Instruction ins=getInstructionAt(toAddr(branch));
        if(ins==null||!ins.getMnemonicString().equalsIgnoreCase("tbb"))throw new IllegalStateException("Expected TBB");
        long start=branch+4;clearListing(toAddr(start),toAddr(start+count-1));
        ArrayList<Address> targets=new ArrayList<>();
        for(int n=0;n<count;n++){
            Address target=toAddr(start+2*Byte.toUnsignedInt(getByte(toAddr(start+n))));targets.add(target);
            new ArmDisassembleCommand(target,null,true).applyTo(currentProgram,monitor);
            ins.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
        }
        Function f=getFunctionAt(toAddr(entry));if(f==null)throw new IllegalStateException("Missing switch function "+Long.toHexString(entry));
        new JumpTable(toAddr(branch),targets,true,0).writeOverride(f);
        CreateFunctionCmd.fixupFunctionBody(currentProgram,f,monitor);
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);
        bounded(0x4092e0L,0x4093a1L,"allocation_code_to_power");
        bounded(0x409dc8L,0x409dd7L,"zero_allocation_row");
        long[][] switches={{0x406e30L,0x406efeL,4},{0x406e30L,0x406f16L,4},{0x406e30L,0x406f5eL,4},
            {0x406e30L,0x407018L,8},{0x407104L,0x407112L,4},{0x407508L,0x407514L,4},{0x407750L,0x40775cL,4},
            {0x4079d0L,0x4079daL,4},{0x407af8L,0x407b02L,4},{0x407bf4L,0x407bfeL,4},
            {0x407d1cL,0x407d26L,4},{0x407e70L,0x407e7eL,4},{0x407fbcL,0x407fc8L,4},
            {0x408180L,0x40818aL,4},{0x408298L,0x4082a2L,4},{0x4083a0L,0x4083aaL,4},
            {0x4092e0L,0x4092eeL,32}};
        for(long[] s:switches)table(s[0],s[1],(int)s[2]);
        long[] entries={0x406b78L,0x406db4L,0x406e30L,0x407104L,0x407508L,0x407750L,
            0x4079d0L,0x407af8L,0x407bf4L,0x407d1cL,0x407e70L,0x407fbcL,
            0x408180L,0x408298L,0x4083a0L,0x4084c8L,0x409078L,0x4092c0L,0x4092e0L,0x4093a2L,0x4093acL,0x409dc8L};
        Gson json=new Gson();DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);
        TreeSet<Long> seen=new TreeSet<>();int count=0;
        try(var funcs=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8);var instructions=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)){
            for(long a:entries){Function f=getFunctionAt(toAddr(a));if(f==null)throw new IllegalStateException("Missing function "+Long.toHexString(a));
                DecompileResults d=dec.decompileFunction(f,45,monitor);Map<String,Object> row=new LinkedHashMap<>();
                row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("decompiled",d.decompileCompleted()?d.getDecompiledFunction().getC():null);row.put("error",d.getErrorMessage());funcs.write(json.toJson(row));funcs.newLine();count++;
                InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
                while(it.hasNext()){Instruction i=it.next();if(!seen.add(i.getAddress().getOffset()))continue;Map<String,Object> r=new LinkedHashMap<>();r.put("address",i.getAddress().toString());r.put("instruction",i.toString());r.put("bytes",HexFormat.of().formatHex(i.getBytes()));instructions.write(json.toJson(r));instructions.newLine();}
            }
        }finally{dec.dispose();}
        ArrayList<Map<String,Object>> tables=new ArrayList<>();
        for(long[] range:new long[][]{{0x2000c2b6L,10},{0x407ab8L,16},{0x408248L,28},{0x473e68L,16}}){Map<String,Object> r=new LinkedHashMap<>();r.put("address",String.format("%08x",range[0]));r.put("hex",HexFormat.of().formatHex(getBytes(toAddr(range[0]),(int)range[1])));tables.add(r);}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);meta.put("exact_function_count",count);meta.put("instruction_records",seen.size());meta.put("tables",tables);
        meta.put("scope","Static scene-dispatch/cap-clamp TBB repairs and selected allocation/helper bodies. Shared register/flag helpers require original instruction review. RAM table comes from reconstructed startup data. No hardware execution.");
        Files.writeString(out.resolve("analysis.json"),json.toJson(meta),StandardCharsets.UTF_8);println("Allocation audit: "+count+" functions, "+seen.size()+" instructions");
    }
}
