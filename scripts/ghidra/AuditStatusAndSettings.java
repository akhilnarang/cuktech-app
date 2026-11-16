// Retain native/packed status distinction and exact stored setting enum paths.
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
 * Exports the difference between native and packed status values, and the exact paths of the
 * stored setting enums. The startup default table is derived memory. A separate check compares it
 * with the expanded block.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-status-settings}</li>
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
public class AuditStatusAndSettings extends GhidraScript {
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
        bounded(0x41f8e8L,0x41f8f1L,"port_widget_state_wrapper");
        bounded(0x41020cL,0x410237L,"port_widget_set_state");
        bounded(0x405f90L,0x405fbdL,"physical_toggle_screen_timeout");
        bounded(0x4142ecL,0x4142f9L,"screen_timeout_callback");
        long[] entries={0x4065c8L,0x41f8e8L,0x41020cL,0x410a18L,0x40c154L,0x40fe08L,0x408f30L,0x408f6cL,0x409e64L,0x40a718L,0x40a5f4L,0x4043acL,0x414554L,0x4152dcL,0x405534L,0x4055ceL,
            0x40476cL,0x404784L,0x404fe8L,0x405a98L,0x405914L,0x405f90L,0x405556L,0x404ab0L,0x4142ecL,0x41ca6cL,0x41ca2cL,0x416168L,0x404954L,0x404918L,0x4048d4L,0x4049fcL,0x404b64L,0x404a5cL,
            0x405d10L,0x405bd8L,0x414c70L,0x41c888L,0x41c910L,0x41c9b4L,0x41c118L,0x41c11cL,0x41c128L};
        Files.createDirectories(out);Gson json=new Gson();int exact=0;DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);
        try(var w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long at:entries) {monitor.checkCancelled();Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",at));Function f=getFunctionAt(toAddr(at));
                if(f==null)row.put("error","No exact entry; no containing-function substitution");
                else {exact++;var r=dec.decompileFunction(f,30,monitor);row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("error",r.getErrorMessage());row.put("decompiled",r.decompileCompleted()?r.getDecompiledFunction().getC():null);}
                w.write(json.toJson(row));w.newLine();}
        }finally{dec.dispose();}
        long[][] ranges={{0x4065c8L,0x406919L},{0x41020cL,0x410237L},{0x408f30L,0x408fa9L},{0x40a85cL,0x40a8f3L},
            {0x4043acL,0x40463fL},{0x414554L,0x4145c1L},{0x41542aL,0x41557fL},{0x405534L,0x40553fL},{0x4055ceL,0x4055d9L},
            {0x40476cL,0x4047c9L},{0x404fe8L,0x40504fL},{0x405914L,0x405b3bL},{0x405f90L,0x405fbdL},
            {0x404ab0L,0x404adbL},{0x4142ecL,0x414327L},{0x41ca2cL,0x41caa7L},{0x4048d4L,0x404a7bL},
            {0x416168L,0x4161fbL},{0x40c700L,0x40c73fL},{0x40c57eL,0x40c6f5L}};
        TreeSet<Long> seen=new TreeSet<>();
        try(var w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long[] r:ranges) {var it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(r[0]),toAddr(r[1])),true);
                while(it.hasNext()) {var ins=it.next();if(!seen.add(ins.getAddress().getOffset()))continue;Map<String,Object> row=new LinkedHashMap<>();row.put("address",ins.getAddress().toString());row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        }
        ArrayList<Map<String,Object>> tables=new ArrayList<>();
        for(long[] r:new long[][]{{0x424f70L,10},{0x405aa8L,17},{0x404ff4L,8},{0x405924L,21},{0x40c740L,16},{0x40c7bcL,8},{0x408facL,4},{0x404780L,4},{0x4049f8L,4},{0x20001768L,20}}) {
            Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",r[0]));row.put("hex",HexFormat.of().formatHex(getBytes(toAddr(r[0]),(int)r[1])));row.put("space",r[0]<0x20000000L?"flash":"reconstructed_startup_sram");tables.add(row);
        }
        ArrayList<Map<String,Object>> refs=new ArrayList<>();
        for(long at:new long[]{0x2000ec1eL,0x2000ec26L,0x405d10L,0x40476cL,0x41020cL})for(Reference ref:getReferencesTo(toAddr(at))) {
            Map<String,Object> row=new LinkedHashMap<>();row.put("target",String.format("%08x",at));row.put("from",ref.getFromAddress().toString());row.put("type",ref.getReferenceType().toString());refs.add(row);}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);meta.put("requested_functions",entries.length);meta.put("exact_function_count",exact);meta.put("tables",tables);meta.put("references",refs);
        meta.put("scope","Static native status/UI/packed status and stored-setting audit. Exact entries only; original bytes govern merged decompiler bodies. Reference absence does not close computed aliases. Startup default table is derived memory, checked separately against expanded block. No ROM/peripheral/controller/hardware execution.");
        Files.writeString(out.resolve("analysis.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH status/settings audit: "+exact+" exact entries / "+seen.size()+" instruction records");
    }
}
