// Static manager/startup-gate/thermal handoff evidence, AD1204 0073 only.
// Arg: new directory. Run -readOnly; annotations are discarded.
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
 * Exports static evidence for the allocation manager, the startup gate and the thermal handoff.
 * It covers the exact manager, callback, elapsed-time, thermal and scheduler entries. It also
 * lists the timestamp literals of the context gate.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-allocation-transitions}</li>
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
public class AuditAllocationTransitions extends GhidraScript {
    // Gives the function at start exactly [start,end] as its body. Removes that range from an
    // enclosing function that has a different entry.
    private void bounded(long start,long end,String name) throws Exception {
        Address entry=toAddr(start);AddressSet range=new AddressSet(entry,toAddr(end));Function old=getFunctionContaining(entry);
        if(old!=null&&!old.getEntryPoint().equals(entry)){AddressSet keep=new AddressSet(old.getBody());keep.delete(range);old.setBody(keep);}
        Function f=getFunctionAt(entry);if(f==null){new ArmDisassembleCommand(entry,null,true).applyTo(currentProgram,monitor);f=createFunction(entry,name);}
        if(f==null)throw new IllegalStateException("Missing entry "+entry);f.setBody(range);f.setName(name,SourceType.USER_DEFINED);
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);Gson json=new Gson();
        bounded(0x409e64L,0x409e83L,"dispatch_desired_cap");bounded(0x40a954L,0x40a99dL,"usb_c_desired_cap_callback");
        bounded(0x409dc8L,0x409dd7L,"zero_cap_row");bounded(0x408c7cL,0x408e43L,"thermal_stage_and_dirty_flag");
        bounded(0x409720L,0x409727L,"manager_with_current_port_mode");bounded(0x409728L,0x409777L,"power_scheduler");
        bounded(0x415d2cL,0x415d2fL,"timer_thunk");bounded(0x415d30L,0x415d43L,"elapsed_timer_units");
        long[] entries={0x4084c8L,0x408760L,0x409720L,0x409728L,0x4092c0L,0x4093ccL,0x409dbcL,0x409dc8L,0x409e64L,0x40a954L,0x415d2cL,0x415d30L,0x408c7cL,0x408f6cL};
        DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);TreeSet<Long> seen=new TreeSet<>();int count=0;
        try(var fw=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8);var iw=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)){
            for(long a:entries){Function f=getFunctionAt(toAddr(a));if(f==null)throw new IllegalStateException("Missing exact function "+Long.toHexString(a));DecompileResults d=dec.decompileFunction(f,35,monitor);Map<String,Object> row=new LinkedHashMap<>();row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("decompiled",d.decompileCompleted()?d.getDecompiledFunction().getC():null);row.put("error",d.getErrorMessage());fw.write(json.toJson(row));fw.newLine();count++;
                var it=currentProgram.getListing().getInstructions(f.getBody(),true);while(it.hasNext()){Instruction i=it.next();if(!seen.add(i.getAddress().getOffset()))continue;Map<String,Object> r=new LinkedHashMap<>();r.put("address",i.getAddress().toString());r.put("instruction",i.toString());r.put("bytes",HexFormat.of().formatHex(i.getBytes()));iw.write(json.toJson(r));iw.newLine();}
            }
        }finally{dec.dispose();}
        ArrayList<Map<String,Object>> literals=new ArrayList<>();
        byte[] raw=getBytes(toAddr(0x403000L),495656);
        for(int n=0;n+3<raw.length;n++){
            long value=(long)(raw[n]&255)|((long)(raw[n+1]&255)<<8)|((long)(raw[n+2]&255)<<16)|((long)(raw[n+3]&255)<<24);
            if(value!=0x2000cea8L&&value!=0x2000ceafL&&value!=0x2000cee4L)continue;
            Address address=toAddr(0x403000L+n);ArrayList<String> users=new ArrayList<>();for(Reference r:getReferencesTo(address))users.add(r.getFromAddress().toString());Map<String,Object> row=new LinkedHashMap<>();row.put("literal_address",address.toString());row.put("value",String.format("%08x",value));row.put("reference_sources",users);literals.add(row);
        }
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);meta.put("exact_function_count",count);meta.put("instruction_records",seen.size());meta.put("context_gate_timestamp_literals",literals);meta.put("scope","Static exact manager/callback/elapsed/thermal/scheduler entries. Repaired shared-body boundaries only in read-only analysis. Literal inventory is a bounded pointer/reference search, not proof against computed/general memory writers. No hardware execution.");Files.writeString(out.resolve("analysis.json"),json.toJson(meta),StandardCharsets.UTF_8);println("Allocation transitions audit: "+count+" functions / "+seen.size()+" instructions");
    }
}
