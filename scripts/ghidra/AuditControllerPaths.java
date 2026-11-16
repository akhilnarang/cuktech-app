// Retain controller writes, cached fields, NV action dispatch and RGB565 UI paths.
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
import java.util.*;
import com.google.gson.Gson;

/**
 * Exports the controller write paths, the cached fields, the NV action dispatch and the RGB565 UI
 * paths. It repairs the measured switch tables in these paths first.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-controller-paths}</li>
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
public class AuditControllerPaths extends GhidraScript {
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
    // Replaces the jump references of one Thumb TBB switch with the destinations read from its byte table.
    private void table(long entry,long branch,long table,int count) throws Exception {
        Instruction ins=getInstructionAt(toAddr(branch));
        if(ins==null||!ins.getMnemonicString().equalsIgnoreCase("tbb"))throw new IllegalStateException("Expected TBB at "+Long.toHexString(branch));
        clearListing(toAddr(table),toAddr(table+count-1));
        ArrayList<Address> targets=new ArrayList<>();
        for(int n=0;n<count;n++) {
            Address target=toAddr(table+2*Byte.toUnsignedInt(getByte(toAddr(table+n))));targets.add(target);
            new ArmDisassembleCommand(target,null,true).applyTo(currentProgram,monitor);
            ins.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
        }
        new JumpTable(toAddr(branch),targets,true,0).writeOverride(getFunctionAt(toAddr(entry)));
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        bounded(0x403ef0L,0x403f7bL,"husb_read_checked");
        bounded(0x414c08L,0x414c2dL,"controller_descending_lookup");
        bounded(0x414c70L,0x414c79L,"controller_lookup_profile");
        bounded(0x41631cL,0x416375L,"sc2021_set_packed_power_limit");
        bounded(0x4217e0L,0x4218abL,"application_queue_worker");
        bounded(0x41fdc4L,0x41fe9dL,"af_factory_dispatch");
        table(0x4217e0L,0x421866L,0x42186aL,5);
        table(0x41fdc4L,0x41fe06L,0x41fe0aL,9);
        Files.createDirectories(out);Gson json=new Gson();
        long[] entries={0x403ef0L,0x403f7cL,0x405194L,0x414c80L,0x414d04L,0x414dacL,0x414e9cL,0x414f44L,0x414f90L,0x40a718L,0x4093ccL,
            0x404008L,0x40407cL,0x40410cL,0x415b3cL,0x415180L,0x4152dcL,0x415670L,0x4158e8L,0x4159ecL,0x415a78L,0x41631cL,
            0x414c08L,0x414c70L,0x405d88L,0x405bd8L,0x405d10L,0x4090a4L,
            0x4217e0L,0x404380L,0x404c08L,0x404a5cL,0x404918L,0x404954L,0x4048d4L,0x4049fcL,0x41c84cL,0x41c854L,0x41c860L,0x41c2d4L,0x41c320L,0x41c348L,0x41413aL,
            0x41fdc4L,0x41c118L,0x41c128L,0x4216c0L,0x4043acL,
            0x40e30cL,0x40e452L,0x41183cL,0x410030L,0x4105b4L};
        DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);int exact=0;
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long at:entries) {
                monitor.checkCancelled();Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",at));Function f=getFunctionAt(toAddr(at));
                if(f==null)row.put("error","No exact entry; no containing-function substitution");
                else {DecompileResults r=dec.decompileFunction(f,30,monitor);exact++;row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("error",r.getErrorMessage());row.put("decompiled",r.decompileCompleted()?r.getDecompiledFunction().getC():null);}
                w.write(json.toJson(row));w.newLine();
            }
        }finally{dec.dispose();}
        long[][] ranges={{0x403ef0L,0x403fffL},{0x414f44L,0x414fd7L},{0x40a718L,0x40a8f3L},{0x4093ccL,0x4094ffL},
            {0x4152dcL,0x415669L},{0x415670L,0x41583bL},{0x415a78L,0x415b7bL},{0x41631cL,0x416375L},
            {0x414c08L,0x414c79L},{0x405bd8L,0x405cdfL},{0x405d10L,0x405d35L},{0x4090a4L,0x4090c3L},{0x405d88L,0x405e19L},
            {0x404380L,0x4043abL},{0x4048d4L,0x404aebL},{0x41c84cL,0x41c86bL},{0x41c2d4L,0x41c37fL},{0x41413aL,0x4141abL},
            {0x4217e0L,0x4218abL},{0x41fdc4L,0x41fe9dL},{0x40e30cL,0x40e451L},{0x4105b4L,0x4107dfL}};
        TreeSet<Long> seen=new TreeSet<>();
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long[] range:ranges) {
                var it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(range[0]),toAddr(range[1])),true);
                while(it.hasNext()) {var ins=it.next();if(!seen.add(ins.getAddress().getOffset()))continue;Map<String,Object> row=new LinkedHashMap<>();row.put("address",ins.getAddress().toString());row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}
            }
        }
        ArrayList<Map<String,Object>> refs=new ArrayList<>();
        for(long at:new long[]{0x403f7cL,0x40410cL,0x415b3cL,0x414f44L,0x414f90L,0x405d10L,0x404a5cL}) {
            for(Reference ref:getReferencesTo(toAddr(at))) {
                Map<String,Object> row=new LinkedHashMap<>();row.put("target",String.format("%08x",at));row.put("from",ref.getFromAddress().toString());row.put("reference_type",ref.getReferenceType().toString());row.put("is_call",ref.getReferenceType().isCall());refs.add(row);
            }
        }
        ArrayList<Map<String,Object>> tables=new ArrayList<>();
        for(long[] range:new long[][]{{0x425074L,136},{0x47397cL,8},{0x4107ecL,64},{0x42186aL,5},{0x41fe0aL,9},{0x4049f8L,4},{0x40a904L,8},{0x405f00L,4}}) {
            Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",range[0]));row.put("hex",HexFormat.of().formatHex(getBytes(toAddr(range[0]),(int)range[1])));tables.add(row);
        }
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);meta.put("requested_functions",entries.length);meta.put("exact_function_count",exact);meta.put("tables",tables);meta.put("incoming_references",refs);
        meta.put("scope","Static, exact-entry controller/configuration/UI audit. Recovered direct calls and data references are separated; computed/ROM closure is not established. No controller operation or whole-system emulation executed. Decompiled warnings remain explicit; original bytes govern.");
        Files.writeString(out.resolve("analysis.json"),json.toJson(meta),StandardCharsets.UTF_8);
        println("CUKTECH controller/asset audit exported "+exact+" exact functions / "+seen.size()+" instruction records");
    }
}
