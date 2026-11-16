// Recover host protocol-settling/control-byte boundaries and retain exact sources.
// Arg: NEW absolute output directory. Use reconstructed 0073 project -readOnly.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.google.gson.Gson;

/**
 * Exports the host protocol settling block, the control-byte boundaries and the state and power
 * helpers. It also exports the SC callback, the startup zero-fill and a raw aligned-literal list.
 * Decompiler C for the snapshot helper is not reliable; the original instructions govern.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-control-settling}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code functions.jsonl}: one row for each requested exact function entry, with body and pseudocode.</li>
 * <li>{@code instructions.jsonl}: the original instruction records and bytes.</li>
 * <li>{@code analysis.json}: image hash, counts and the scope of the evidence.</li>
 * </ul>
 *
 * Program changes: it disassembles exact function entries and sets their bodies and names.
 * It does not change firmware bytes.
 * Run it with {@code -readOnly} on a project copy, so that Ghidra discards these changes.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output directory already exists.
 */
public class AuditControlSettling extends GhidraScript {
    // Gives the function at start exactly [start,end] as its body. Removes that range from an
    // enclosing function that has a different entry.
    private void bounded(long start,long end,String name) throws Exception {
        Address entry=toAddr(start);AddressSet body=new AddressSet(entry,toAddr(end));Function old=getFunctionContaining(entry);
        if(old!=null&&!old.getEntryPoint().equals(entry)){AddressSet rest=new AddressSet(old.getBody());rest.delete(body);old.setBody(rest);}
        Function f=getFunctionAt(entry);if(f==null){new ArmDisassembleCommand(entry,null,true).applyTo(currentProgram,monitor);f=createFunction(entry,name);}
        if(f==null)throw new IllegalStateException("No exact entry "+entry);f.setBody(body);f.setName(name,SourceType.USER_DEFINED);
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        bounded(0x409f38L,0x40a161L,"sc_protocol_report_callback");
        bounded(0x4030d0L,0x4030ddL,"startup_zero_fill");
        bounded(0x4158d8L,0x4158e5L,"sc_cached_fields_getter");
        bounded(0x4053acL,0x4053bfL,"snapshot_cached_protocol_power_register_helper");
        long[] entries={0x4030d0L,0x4093ccL,0x40a5f4L,0x4095ecL,0x409698L,0x4096b8L,0x4096d8L,0x409e84L,
            0x409ee4L,0x409f14L,0x4053acL,0x409becL,0x409c1cL,0x409d08L,0x405e5cL,0x40a718L,0x409728L,0x409f38L,0x4158d8L};
        Files.createDirectories(out);Gson json=new Gson();int exact=0;DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);
        try(var w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)){
            for(long at:entries){monitor.checkCancelled();Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",at));Function f=getFunctionAt(toAddr(at));
                if(f==null)row.put("error","No exact entry; no containing-function substitution");
                else{exact++;var r=dec.decompileFunction(f,30,monitor);row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("error",r.getErrorMessage());row.put("decompiled",r.decompileCompleted()?r.getDecompiledFunction().getC():null);}w.write(json.toJson(row));w.newLine();}
        }finally{dec.dispose();}
        long[][] ranges={{0x403090L,0x4030b5L},{0x4030d0L,0x4030ddL},{0x4093ccL,0x40945fL},{0x40a5f4L,0x40a6a3L},
            {0x4053acL,0x4053bfL},{0x4054eeL,0x4054f3L},{0x409becL,0x409cc9L},{0x409d08L,0x409d6dL},
            {0x405e5cL,0x405ea7L},{0x40a81cL,0x40a82dL},{0x40a89aL,0x40a903L},{0x409728L,0x409783L},
            {0x409f38L,0x40a161L},{0x4158d8L,0x4158e5L}};
        TreeSet<Long> seen=new TreeSet<>();try(var w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)){
            for(long[] r:ranges){var it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(r[0]),toAddr(r[1])),true);while(it.hasNext()){var ins=it.next();if(!seen.add(ins.getAddress().getOffset()))continue;Map<String,Object> row=new LinkedHashMap<>();row.put("address",ins.getAddress().toString());row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        }
        ArrayList<Map<String,Object>> references=new ArrayList<>();
        for(long at:new long[]{0x2000cf3dL,0x2000cf42L,0x2000ce94L,0x2000ce95L})for(Reference r:getReferencesTo(toAddr(at))){Map<String,Object> row=new LinkedHashMap<>();row.put("target",String.format("%08x",at));row.put("from",r.getFromAddress().toString());row.put("type",r.getReferenceType().toString());references.add(row);}
        ArrayList<Map<String,Object>> aliases=new ArrayList<>();
        // Raw-image aligned literal inventory only; no computed-alias closure.
        for(long at=0x403000L;at+4<=0x47c028L;at+=4){long value=Integer.toUnsignedLong(getInt(toAddr(at)));if(value!=0x2000cf28L&&value!=0x2000cf3aL&&value!=0x2000cf3fL&&!(value>=0x2000ce70L&&value<=0x2000ce95L))continue;
            Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",at));row.put("target",String.format("%08x",value));ArrayList<Map<String,Object>> users=new ArrayList<>();for(Reference r:getReferencesTo(toAddr(at))){Map<String,Object> user=new LinkedHashMap<>();user.put("from",r.getFromAddress().toString());Function f=getFunctionContaining(r.getFromAddress());user.put("function",f==null?null:f.getEntryPoint().toString());users.add(user);}row.put("annotated_users",users);aliases.add(row);
        }
        ArrayList<Map<String,Object>> tables=new ArrayList<>();for(long[] r:new long[][]{{0x403120L,16},{0x409d7cL,11},{0x40a6e0L,4}}){Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",r[0]));row.put("hex",HexFormat.of().formatHex(getBytes(toAddr(r[0]),(int)r[1])));tables.add(row);}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);meta.put("requested_functions",entries.length);meta.put("exact_function_count",exact);meta.put("instruction_records",seen.size());meta.put("field_references",references);meta.put("aligned_raw_literals",aliases);meta.put("tables",tables);
        meta.put("scope","Exact original settling/state/power instructions and SC callback/zero-fill/cache-tail evidence. Snapshot helper uses live r4/r8 and returns multiple registers; empty/incorrect decompiler C is not authoritative. Direct references and raw aligned literals are bounded evidence, not exhaustive alias or dynamic-writer proof. No hardware/bus/ROM execution; read-only changes discarded.");Files.writeString(out.resolve("analysis.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH control/settling audit: "+exact+" exact functions / "+seen.size()+" instruction records");
    }
}
