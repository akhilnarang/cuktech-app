// Retain exact packet-field consumers, pointer aliases and named policy strings.
// Arg: new absolute output directory; use the reconstructed project -readOnly.
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
 * Exports the exact functions that read controller packet fields, the pointer aliases of these
 * fields and the named policy strings. Data references are not a full alias closure.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-controller-fields}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code functions.jsonl}: one row for each requested exact function entry, with body and pseudocode.</li>
 * <li>{@code instructions.jsonl}: the original instruction records and bytes.</li>
 * <li>{@code analysis.json}: image hash, counts and the scope of the evidence.</li>
 * </ul>
 *
 * Program changes: it disassembles exact function entries and sets their bodies.
 * It does not change firmware bytes.
 * Run it with {@code -readOnly} on a project copy, so that Ghidra discards these changes.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output directory already exists.
 */
public class AuditControllerFields extends GhidraScript {
    // Gives the function at start exactly [start,end] as its body. Removes that range from an
    // enclosing function that has a different entry.
    private void bounded(long start,long end,String name) throws Exception {
        Address entry=toAddr(start);AddressSet body=new AddressSet(entry,toAddr(end));Function old=getFunctionContaining(entry);
        if(old!=null&&!old.getEntryPoint().equals(entry)){AddressSet rest=new AddressSet(old.getBody());rest.delete(body);old.setBody(rest);}
        Function f=getFunctionAt(entry);if(f==null){new ArmDisassembleCommand(entry,null,true).applyTo(currentProgram,monitor);f=createFunction(entry,name);}
        if(f==null)throw new IllegalStateException("No exact entry "+entry);f.setBody(body);
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        bounded(0x403ef0L,0x403f7bL,"husb_read_checked");
        bounded(0x4158d8L,0x4158e5L,"sc_cached_fields_getter");
        long[] entries={0x403ef0L,0x414c80L,0x414dacL,0x414e9cL,0x405e5cL,0x406364L,0x406b78L,0x406db4L,
            0x40a718L,0x40a57cL,0x40a5f4L,0x4093ccL,0x4146bcL,0x4152dcL,0x415670L,0x415a78L,0x4159ecL,
            0x41f77cL,0x406a74L,0x40d700L,0x41cae4L,0x4158d8L};
        Files.createDirectories(out);Gson json=new Gson();int exact=0;DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);
        try(var w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long at:entries){monitor.checkCancelled();Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",at));Function f=getFunctionAt(toAddr(at));
                if(f==null)row.put("error","No exact entry; no containing-function substitution");
                else{exact++;var r=dec.decompileFunction(f,30,monitor);row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("error",r.getErrorMessage());row.put("decompiled",r.decompileCompleted()?r.getDecompiledFunction().getC():null);}
                w.write(json.toJson(row));w.newLine();}
        }finally{dec.dispose();}
        long[][] ranges={{0x403ef0L,0x403f7bL},{0x414c80L,0x414cdbL},{0x414dacL,0x414e2bL},{0x414e9cL,0x414edfL},
            {0x405e5cL,0x405ea7L},{0x406b78L,0x406e25L},{0x40a57cL,0x40a5cbL},{0x40a5f4L,0x40a6a3L},
            {0x40a718L,0x40a903L},{0x40997cL,0x409a47L},{0x4089ceL,0x408a25L},{0x4146bcL,0x4146ebL},
            {0x4152dcL,0x4155c5L},{0x415670L,0x41583dL},{0x415a78L,0x415b35L},{0x41f77cL,0x41f78fL},
            {0x40678eL,0x40679dL},{0x406a74L,0x406a8dL},{0x40d700L,0x40d82dL},{0x41cae4L,0x41cb33L},
            {0x4158d8L,0x4158e5L},{0x409f7eL,0x409f97L},{0x409fd4L,0x409fe9L}};
        TreeSet<Long> seen=new TreeSet<>();
        try(var w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long[] r:ranges){var it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(r[0]),toAddr(r[1])),true);
                while(it.hasNext()){var ins=it.next();if(!seen.add(ins.getAddress().getOffset()))continue;Map<String,Object> row=new LinkedHashMap<>();row.put("address",ins.getAddress().toString());row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        }
        ArrayList<Map<String,Object>> refs=new ArrayList<>();
        for(long[] span:new long[][]{{0x2000cf80L,0x24},{0x2000c998L,0x0c},{0x2000ce96L,17},{0x2000cd4cL,4},{0x2000c60cL,18},{0x2000cf28L,1}}) {
            for(long n=0;n<span[1];n++)for(Reference r:getReferencesTo(toAddr(span[0]+n))){Map<String,Object> row=new LinkedHashMap<>();row.put("target",String.format("%08x",span[0]+n));row.put("from",r.getFromAddress().toString());row.put("type",r.getReferenceType().toString());Function parent=getFunctionContaining(r.getFromAddress());row.put("containing_function",parent==null?null:parent.getEntryPoint().toString());refs.add(row);}
        }
        ArrayList<Map<String,Object>> literals=new ArrayList<>();
        for(long at:new long[]{0x406da8L,0x408c50L,0x409b04L,0x40a6e0L,0x41cb44L,0x41f794L}){
            Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",at));row.put("bytes",HexFormat.of().formatHex(getBytes(toAddr(at),4)));long target=Integer.toUnsignedLong(getInt(toAddr(at)));row.put("target",String.format("%08x",target));
            if(target>=0x403000L&&target<0x47c028L){ArrayList<Byte> bytes=new ArrayList<>();for(int n=0;n<240;n++){byte b=getByte(toAddr(target+n));if(b==0)break;bytes.add(b);}byte[] data=new byte[bytes.size()];for(int n=0;n<data.length;n++)data[n]=bytes.get(n);row.put("ascii",new String(data,StandardCharsets.US_ASCII));}literals.add(row);}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);meta.put("requested_functions",entries.length);meta.put("exact_function_count",exact);meta.put("instruction_records",seen.size());meta.put("incoming_field_references",refs);meta.put("literals",literals);
        meta.put("scope","Static exact field consumers and annotated data references in retained Ghidra program. References are not computed-alias closure. Original instructions govern register arguments; no bus/ROM/hardware execution. Missing ROM/decompiler warnings remain explicit; read-only changes discarded.");
        Files.writeString(out.resolve("analysis.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH controller fields: "+exact+" exact functions / "+seen.size()+" instruction records");
    }
}
