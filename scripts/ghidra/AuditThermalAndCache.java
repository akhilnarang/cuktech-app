// Retain thermal/display derivation and independent MIOT/native cache evidence.
// Analyst annotations only. Arg: new absolute output directory. Use -readOnly.
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
import java.util.*;
import com.google.gson.Gson;

/**
 * Exports the thermal and display value derivation, with the load and correction switches.
 * It also exports the MIOT cache and the native cache as separate evidence.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-thermal-cache}</li>
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
public class AuditThermalAndCache extends GhidraScript {
    // Gives the function at start exactly [start,end] as its body. Removes that range from an
    // enclosing function that has a different entry.
    private void bounded(long start,long end,String name) throws Exception {
        Address entry=toAddr(start);AddressSet range=new AddressSet(entry,toAddr(end));
        Function old=getFunctionContaining(entry);
        if(old!=null&&!old.getEntryPoint().equals(entry)) {
            AddressSet retained=new AddressSet(old.getBody());retained.delete(range);old.setBody(retained);
        }
        Function f=getFunctionAt(entry);
        if(f==null) {new ArmDisassembleCommand(entry,null,true).applyTo(currentProgram,monitor);f=createFunction(entry,name);}
        if(f==null)throw new IllegalStateException("Missing exact entry: "+entry);
        f.setBody(range);f.setName(name,SourceType.USER_DEFINED);
    }
    private List<Map<String,Object>> switchTable(long function,long branch,long table,int count) throws Exception {
        Instruction instruction=getInstructionAt(toAddr(branch));
        if(instruction==null||!instruction.getMnemonicString().equalsIgnoreCase("tbb"))throw new IllegalStateException("Expected measured TBB");
        clearListing(toAddr(table),toAddr(table+count-1));
        ArrayList<Address> targets=new ArrayList<>();ArrayList<Map<String,Object>> rows=new ArrayList<>();
        for(int index=0;index<count;index++) {
            int encoded=Byte.toUnsignedInt(getByte(toAddr(table+index)));Address target=toAddr(table+2*encoded);targets.add(target);
            new ArmDisassembleCommand(target,null,true).applyTo(currentProgram,monitor);
            instruction.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
            Map<String,Object> row=new LinkedHashMap<>();row.put("index",index);row.put("table_byte",encoded);row.put("target",target.toString());rows.add(row);
        }
        new JumpTable(toAddr(branch),targets,true,0).writeOverride(getFunctionAt(toAddr(function)));return rows;
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        Files.createDirectories(out);Gson json=new Gson();
        bounded(0x409728L,0x409777L,"controller_poll_scheduler");
        bounded(0x408c7cL,0x408e43L,"thermal_stage_and_display_value");
        bounded(0x406aa4L,0x406ad5L,"publish_thermal_display_value");
        bounded(0x4090a4L,0x4092b5L,"load_corrected_shell_input");
        bounded(0x4092c0L,0x4092d5L,"thermal_budget_lookup");
        bounded(0x408f6cL,0x408fabL,"controller_error_clear_handshake");
        bounded(0x4050d0L,0x4050e5L,"set_miot_cache_updates");
        List<Map<String,Object>> correctionSwitch=switchTable(0x4090a4L,0x4092a0L,0x4092a4L,4);
        List<Map<String,Object>> loadSwitch=switchTable(0x4090a4L,0x4090bcL,0x4090c0L,8);
        long[] entries={0x408c7cL,0x406aa4L,0x4090a4L,0x4092c0L,0x408f6cL,0x409728L,
            0x4093ccL,0x41f894L,0x410130L,0x4050d0L,0x4043acL,0x405914L,
            0x405e5cL,0x414dacL,0x40a718L,0x415060L,0x41c9b4L,0x4165d4L,
            0x410a28L,0x409c1cL,0x409d08L,0x4084c8L,0x406e30L,0x405d54L,0x405d70L};
        DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);int count=0;
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long at:entries) {
                Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",at));Function f=getFunctionAt(toAddr(at));
                if(f==null)row.put("error","No exact entry; no containing-function substitution");
                else {DecompileResults r=dec.decompileFunction(f,30,monitor);count++;row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("error",r.getErrorMessage());row.put("decompiled",r.decompileCompleted()?r.getDecompiledFunction().getC():null);}
                w.write(json.toJson(row));w.newLine();
            }
        }finally{dec.dispose();}
        long[][] ranges={{0x408c7cL,0x408e43L},{0x4090a4L,0x4092b5L},{0x406aa4L,0x406ad5L},
            {0x4092c0L,0x4092d5L},{0x408f6cL,0x408fabL},{0x409728L,0x409777L},
            {0x41f894L,0x41f8bbL},{0x4043acL,0x4043b3L},{0x4044c0L,0x404517L},
            {0x4050d0L,0x4050e5L},{0x41fde0L,0x41fde5L},{0x4165d4L,0x41660bL},
            {0x4053acL,0x4053bfL},{0x409c90L,0x409cceL},{0x409d08L,0x409d45L},
            {0x408618L,0x40865bL},{0x410a28L,0x410a7fL},{0x405d54L,0x405d95L}};
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long[] range:ranges) {
                InstructionIterator iterator=currentProgram.getListing().getInstructions(new AddressSet(toAddr(range[0]),toAddr(range[1])),true);
                while(iterator.hasNext()) {Instruction i=iterator.next();Map<String,Object> row=new LinkedHashMap<>();row.put("address",i.getAddress().toString());row.put("instruction",i.toString());row.put("bytes",HexFormat.of().formatHex(i.getBytes()));w.write(json.toJson(row));w.newLine();}
            }
        }
        ArrayList<Map<String,Object>> tables=new ArrayList<>();
        for(long[] range:new long[][]{{0x473e68L,0x34},{0x408e78L,8},{0x409460L,4},{0x4050e8L,4}}) {
            Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",range[0]));row.put("hex",HexFormat.of().formatHex(getBytes(toAddr(range[0]),(int)range[1])));tables.add(row);
        }
        Map<String,Object> metadata=new LinkedHashMap<>();metadata.put("sha256",sha);metadata.put("exact_function_count",count);metadata.put("requested_functions",entries.length);
        metadata.put("load_switch",loadSwitch);metadata.put("correction_switch",correctionSwitch);metadata.put("tables",tables);
        metadata.put("scope","Static thermal/cache code and original tables; annotations discarded by read-only processing. No charger commands or hardware validation.");
        Files.writeString(out.resolve("analysis.json"),json.toJson(metadata),StandardCharsets.UTF_8);
        println("CUKTECH thermal/cache audit exported "+count+" exact functions");
    }
}
