// Retain protocol-enable naming/arguments and AF/action command validation.
// Arg: new absolute output directory. Analyst annotations only; use -readOnly.
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
 * Exports the protocol-enable functions with their names and argument order, the protocol-log
 * formats, the AF command byte order and ACK paths, and the action registration and validation.
 * The name of native protocol 9 is not known.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-protocol-commands}</li>
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
public class AuditProtocolAndCommands extends GhidraScript {
    // Gives the function at start exactly [start,end] as its body. Removes that range from an
    // enclosing function that has a different entry.
    private void bounded(long start,long end,String name) throws Exception {
        Address entry=toAddr(start);AddressSet range=new AddressSet(entry,toAddr(end));Function old=getFunctionContaining(entry);
        if(old!=null&&!old.getEntryPoint().equals(entry)) {AddressSet retained=new AddressSet(old.getBody());retained.delete(range);old.setBody(retained);}
        Function f=getFunctionAt(entry);if(f==null) {new ArmDisassembleCommand(entry,null,true).applyTo(currentProgram,monitor);f=createFunction(entry,name);}
        if(f==null)throw new IllegalStateException("No exact entry "+entry);f.setBody(range);f.setName(name,SourceType.USER_DEFINED);
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        bounded(0x409698L,0x4096b5L,"husb_set_pd_enable");bounded(0x4096b8L,0x4096d5L,"husb_set_pps_enable");
        bounded(0x40546eL,0x40547fL,"husb_disable_bit_common");bounded(0x4054feL,0x405503L,"log_with_port_from_r4");
        bounded(0x405382L,0x40538fL,"auto_test_clear_protocol_disable_bits");bounded(0x40540eL,0x405415L,"auto_test_store_disable_byte");
        long[] entries={0x409e84L,0x409698L,0x4096b8L,0x40546eL,0x4054feL,0x40a5f4L,0x408eccL,0x414f90L,0x414dacL,0x406364L,0x4087b0L,0x405382L,0x40540eL,0x40d2e0L,0x404dd0L,0x4158e8L,0x408fd0L,0x40a2a4L,
            0x422338L,0x4223a8L,0x405120L,0x42165cL,0x41ba00L,0x41be70L,0x41bf54L,0x41c020L,0x41fee4L,0x41d368L};
        Files.createDirectories(out);Gson json=new Gson();int exact=0;DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);
        try(var w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long at:entries) {monitor.checkCancelled();Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",at));Function f=getFunctionAt(toAddr(at));
                if(f==null)row.put("error","No exact entry; no containing-function substitution");
                else {exact++;var r=dec.decompileFunction(f,30,monitor);row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("error",r.getErrorMessage());row.put("decompiled",r.decompileCompleted()?r.getDecompiledFunction().getC():null);}
                w.write(json.toJson(row));w.newLine();}
        }finally{dec.dispose();}
        long[][] ranges={{0x409e84L,0x409edfL},{0x409698L,0x4096d5L},{0x40546eL,0x40547fL},{0x4054feL,0x405503L},{0x405382L,0x40538fL},{0x40540eL,0x405415L},
            {0x404dd0L,0x404fe7L},{0x40a5f4L,0x40a6a3L},{0x408eccL,0x408f0bL},{0x409826L,0x409859L},{0x409902L,0x409939L},{0x406364L,0x4063fbL},
            {0x422338L,0x4223ebL},{0x41d368L,0x41d38dL},{0x42165cL,0x42169fL},{0x41ba00L,0x41ba1fL},{0x41be70L,0x41bf53L}};
        TreeSet<Long> seen=new TreeSet<>();
        try(var w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long[] r:ranges) {var it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(r[0]),toAddr(r[1])),true);
                while(it.hasNext()) {var ins=it.next();if(!seen.add(ins.getAddress().getOffset()))continue;Map<String,Object> row=new LinkedHashMap<>();row.put("address",ins.getAddress().toString());row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        }
        ArrayList<Map<String,Object>> tables=new ArrayList<>();
        for(long[] r:new long[][]{{0x408fe8L,32},{0x41fe0aL,9},{0x4223a0L,8},{0x4223ecL,4},{0x4216acL,4},{0x409af8L,12},{0x409ee0L,4},{0x40a6dcL,4}}) {
            Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",r[0]));row.put("hex",HexFormat.of().formatHex(getBytes(toAddr(r[0]),(int)r[1])));tables.add(row);}
        ArrayList<Map<String,Object>> formats=new ArrayList<>();
        for(long at:new long[]{0x475117L,0x475170L,0x4753d5L}) {ArrayList<Byte> bytes=new ArrayList<>();for(int n=0;n<160;n++) {byte b=getByte(toAddr(at+n));if(b==0)break;bytes.add(b);}byte[] b=new byte[bytes.size()];for(int n=0;n<b.length;n++)b[n]=bytes.get(n);Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",at));row.put("hex",HexFormat.of().formatHex(b));row.put("ascii",new String(b,StandardCharsets.US_ASCII));formats.add(row);}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);meta.put("requested_functions",entries.length);meta.put("exact_function_count",exact);meta.put("tables",tables);meta.put("log_formats",formats);
        meta.put("scope","Static protocol-control naming, AAPCS argument order, AF command byte order/ACK limits and action callback validation. Native protocol9 naming remains unresolved. Exact entries only; original instructions govern shared-register/decompiler boundaries. No hardware/controller operation executed.");
        Files.writeString(out.resolve("analysis.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH protocol/command audit: "+exact+" exact functions / "+seen.size()+" instruction records");
    }
}
