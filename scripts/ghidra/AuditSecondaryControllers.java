// Exact-entry secondary-controller/bus follow-up; annotations discarded with -readOnly.
// Arg: new absolute output directory. No target/controller code is executed.
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
 * Exports the exact entries of the secondary controller and bus functions. It repairs the TBB
 * switch at 0x004092f2 first. No controller code runs.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-secondary-controllers}</li>
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
public class AuditSecondaryControllers extends GhidraScript {
    // Gives the function at start exactly [start,end] as its body. Removes that range from an
    // enclosing function that has a different entry.
    private void bounded(long start,long end,String name) throws Exception {
        Address entry=toAddr(start);AddressSet range=new AddressSet(entry,toAddr(end));Function old=getFunctionContaining(entry);
        if(old!=null&&!old.getEntryPoint().equals(entry)) {AddressSet rest=new AddressSet(old.getBody());rest.delete(range);old.setBody(rest);}
        Function f=getFunctionAt(entry);
        if(f==null) {new ArmDisassembleCommand(entry,null,true).applyTo(currentProgram,monitor);f=createFunction(entry,name);}
        if(f==null)throw new IllegalStateException("No exact entry "+entry);
        f.setBody(range);f.setName(name,SourceType.USER_DEFINED);
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        bounded(0x403ef0L,0x403f7bL,"husb_read_checked");
        bounded(0x40a498L,0x40a545L,"sc_allocator_callback");
        bounded(0x41631cL,0x416375L,"sc_set_packed_limit");
        bounded(0x4092e0L,0x4093a1L,"allocation_code_to_deciwatts");
        var branch=getInstructionAt(toAddr(0x4092eeL));
        if(branch==null||!branch.getMnemonicString().equalsIgnoreCase("tbb"))throw new IllegalStateException("Expected cap TBB");
        clearListing(toAddr(0x4092f2L),toAddr(0x409311L));
        ArrayList<Address> targets=new ArrayList<>();
        for(int n=0;n<32;n++) {Address target=toAddr(0x4092f2L+2*Byte.toUnsignedInt(getByte(toAddr(0x4092f2L+n))));targets.add(target);new ArmDisassembleCommand(target,null,true).applyTo(currentProgram,monitor);branch.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);}
        new JumpTable(toAddr(0x4092eeL),targets,true,0).writeOverride(getFunctionAt(toAddr(0x4092e0L)));
        long[] entries={0x403ef0L,0x403f7cL,0x40410cL,0x4041b4L,0x404298L,0x4042c4L,
            0x40868cL,0x4092e0L,0x4093a2L,0x409e64L,0x40a498L,0x415244L,0x4152dcL,0x4158e8L,0x415b3cL,0x41631cL};
        Files.createDirectories(out);Gson json=new Gson();int exact=0;DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);
        try(var w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long at:entries) {monitor.checkCancelled();Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",at));Function f=getFunctionAt(toAddr(at));
                if(f==null)row.put("error","No exact entry; no containing-function substitution");
                else {exact++;var r=dec.decompileFunction(f,30,monitor);row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());row.put("error",r.getErrorMessage());row.put("decompiled",r.decompileCompleted()?r.getDecompiledFunction().getC():null);}
                w.write(json.toJson(row));w.newLine();}
        }finally{dec.dispose();}
        long[][] ranges={{0x403ef0L,0x403fffL},{0x40410cL,0x404139L},{0x4041b4L,0x404221L},{0x40424cL,0x4042d7L},
            {0x40868cL,0x4086b9L},{0x4092e0L,0x4093a9L},{0x409e64L,0x409e83L},{0x40a498L,0x40a545L},
            {0x415244L,0x4152a5L},{0x4154b8L,0x4154fbL},{0x4158e8L,0x41595dL},{0x415b3cL,0x415b77L},{0x41631cL,0x416375L}};
        TreeSet<Long> seen=new TreeSet<>();
        try(var w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long[] r:ranges) {var it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(r[0]),toAddr(r[1])),true);
                while(it.hasNext()) {var ins=it.next();if(!seen.add(ins.getAddress().getOffset()))continue;Map<String,Object> row=new LinkedHashMap<>();row.put("address",ins.getAddress().toString());row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        }
        ArrayList<Map<String,Object>> literals=new ArrayList<>();
        for(long at:new long[]{0x414cdcL,0x414fc8L,0x415634L,0x416378L,0x40a548L,0x414c7cL,0x415058L,0x41505cL,0x418e7cL,0x41277cL,0x41286cL}) {
            Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",at));row.put("hex",HexFormat.of().formatHex(getBytes(toAddr(at),4)));literals.add(row);}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);meta.put("requested_functions",entries.length);meta.put("exact_function_count",exact);meta.put("literals",literals);meta.put("instruction_records",seen.size());
        meta.put("scope","Static bus framing, SC allocator/limit/protocol cache paths and known table pointers. Original bytes govern signatures and merged helpers. No bus/controller/target execution; no complete computed-call/ROM closure.");
        Files.writeString(out.resolve("analysis.json"),json.toJson(meta),StandardCharsets.UTF_8);
        println("CUKTECH secondary controller audit: "+exact+" exact functions / "+seen.size()+" instruction records");
    }
}
