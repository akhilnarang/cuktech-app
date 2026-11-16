// Retain sensor meanings, factory calibration provenance and thermal status UI.
// Arg: new absolute output directory. Analyst annotations only; use -readOnly.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.Gson;

/**
 * Exports the sensor meanings, the factory calibration source and the thermal status UI.
 * It also records the copied factory loader at 0x00201344 (0x6c bytes).
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-sensor-calibration}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code functions.jsonl}: one row for each requested exact function entry, with body and pseudocode.</li>
 * <li>{@code instructions.jsonl}: the original instruction records and bytes.</li>
 * <li>{@code analysis.json}: image hash, counts and the scope of the evidence.</li>
 * </ul>
 *
 * Program changes: it sets exact function bodies and names, clears and disassembles
 * measured switch tables and adds jump references. It does not change firmware bytes.
 * Run it with {@code -readOnly} on a project copy, so that Ghidra discards these changes.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output directory already exists.
 */
public class AuditSensorCalibration extends GhidraScript {
    // Gives the function at start exactly [start,end] as its body. Removes that range from an
    // enclosing function that has a different entry.
    private void bounded(long start,long end,String name) throws Exception {
        Address entry=toAddr(start);AddressSet range=new AddressSet(entry,toAddr(end));
        Function old=getFunctionContaining(entry);
        if(old!=null&&!old.getEntryPoint().equals(entry)) {AddressSet retained=new AddressSet(old.getBody());retained.delete(range);old.setBody(retained);}
        Function f=getFunctionAt(entry);
        if(f==null) {new ArmDisassembleCommand(entry,null,true).applyTo(currentProgram,monitor);f=createFunction(entry,name);}
        if(f==null)throw new IllegalStateException("No exact entry at "+entry);
        f.setBody(range);f.setName(name,SourceType.USER_DEFINED);
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        byte[] loader=getBytes(toAddr(0x201344L),0x6c);
        if(!Arrays.equals(loader,getBytes(toAddr(0x477824L),0x6c)))throw new IllegalStateException("Copied loader disagrees with original flash bytes");
        Files.createDirectories(out);Gson json=new Gson();
        bounded(0x4220fcL,0x422129L,"read_ac_sense_proxy");
        bounded(0x414b5cL,0x414b8fL,"set_pfc_state");
        bounded(0x4092e0L,0x4093a1L,"allocation_code_to_power");
        Address branch=toAddr(0x4092eeL);Instruction instruction=getInstructionAt(branch);
        if(instruction==null||!instruction.getMnemonicString().equalsIgnoreCase("tbb"))throw new IllegalStateException("Expected cap TBB");
        clearListing(toAddr(0x4092f2L),toAddr(0x409311L));
        ArrayList<Address> destinations=new ArrayList<>();
        for(int index=0;index<32;index++) {
            Address target=toAddr(0x4092f2L+2*Byte.toUnsignedInt(getByte(toAddr(0x4092f2L+index))));destinations.add(target);
            new ArmDisassembleCommand(target,null,true).applyTo(currentProgram,monitor);
            instruction.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
        }
        new JumpTable(branch,destinations,true,0).writeOverride(getFunctionAt(toAddr(0x4092e0L)));
        long[] entries={0x201344L,0x412248L,0x41234cL,0x41236cL,0x4146ecL,0x41478cL,
            0x41216cL,0x412408L,0x41382cL,0x41390cL,0x41503cL,0x415670L,
            0x411becL,0x4220fcL,0x414a7cL,0x414ac0L,0x414b08L,0x414b48L,
            0x414b54L,0x414b5cL,0x4092e0L,0x4093a2L,0x41e5c4L,0x40488cL,
            0x405834L,0x4058bcL,0x414e9cL,0x40b0b0L,0x4105b4L,0x404d2cL};
        DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);int count=0;
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long at:entries) {
                Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",at));Function f=getFunctionAt(toAddr(at));
                if(f==null)row.put("error","No exact entry; no containing-function substitution");
                else {DecompileResults r=dec.decompileFunction(f,30,monitor);count++;row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("error",r.getErrorMessage());row.put("decompiled",r.decompileCompleted()?r.getDecompiledFunction().getC():null);}
                w.write(json.toJson(row));w.newLine();
            }
        }finally{dec.dispose();}
        long[][] ranges={{0x412248L,0x4122abL},{0x41234cL,0x412371L},{0x4146ecL,0x4147a1L},
            {0x41503cL,0x415057L},{0x4220fcL,0x422129L},{0x414a7cL,0x414b2bL},
            {0x414b48L,0x414b8fL},{0x4092e0L,0x4093a9L},{0x410738L,0x410743L},
            {0x404d90L,0x404dbbL}};
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long[] range:ranges) {
                InstructionIterator it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(range[0]),toAddr(range[1])),true);
                while(it.hasNext()) {Instruction i=it.next();Map<String,Object> row=new LinkedHashMap<>();row.put("address",i.getAddress().toString());row.put("instruction",i.toString());row.put("bytes",HexFormat.of().formatHex(i.getBytes()));w.write(json.toJson(row));w.newLine();}
            }
        }
        ArrayList<Map<String,Object>> tables=new ArrayList<>();
        for(long[] range:new long[][]{{0x424f98L,126},{0x425016L,94},{0x4092f2L,32},{0x475c1aL,23}}) {
            Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",range[0]));row.put("hex",HexFormat.of().formatHex(getBytes(toAddr(range[0]),(int)range[1])));tables.add(row);
        }
        Map<String,Object> copy=new LinkedHashMap<>();copy.put("runtime_address","00201344");copy.put("source_address","00477824");copy.put("file_offset","00074824");
        copy.put("hex",HexFormat.of().formatHex(loader));copy.put("sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(loader)));
        Map<String,Object> metadata=new LinkedHashMap<>();metadata.put("sha256",sha);metadata.put("exact_function_count",count);metadata.put("requested_functions",entries.length);
        metadata.put("copied_factory_loader",copy);metadata.put("tables",tables);
        metadata.put("scope","Static calibration/sensor code. Copied loader source checked separately; instruction export contains flash addresses only. ROM checksum/acquisition/hardware behavior not executed; decompiler warnings retained.");
        Files.writeString(out.resolve("analysis.json"),json.toJson(metadata),StandardCharsets.UTF_8);
        println("CUKTECH sensor/calibration audit exported "+count+" exact functions");
    }
}
