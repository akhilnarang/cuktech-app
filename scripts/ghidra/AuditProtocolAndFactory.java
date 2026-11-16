// Recover the measured factory LCD renderer and retain protocol-code evidence.
// Analyst annotations only. Args: new absolute output directory; use -readOnly.
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
 * Recovers the measured factory LCD renderer and its eight switch destinations. It also exports
 * the protocol-code evidence.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-protocol-factory}</li>
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
public class AuditProtocolAndFactory extends GhidraScript {
    // Gives the function at start exactly [start,end] as its body. Removes that range from an
    // enclosing function that has a different entry.
    private void bounded(long start,long end,String name) throws Exception {
        Address entry=toAddr(start);AddressSet range=new AddressSet(entry,toAddr(end));
        Function old=getFunctionContaining(entry);
        if(old!=null&&!old.getEntryPoint().equals(entry)) {
            AddressSet retained=new AddressSet(old.getBody());retained.delete(range);
            old.setBody(retained);
        }
        Function f=getFunctionAt(entry);
        if(f==null) {
            new ArmDisassembleCommand(entry,null,true).applyTo(currentProgram,monitor);
            f=createFunction(entry,name);
        }
        if(f==null)throw new IllegalStateException("No exact factory function at "+entry);
        f.setBody(range);f.setName(name,SourceType.USER_DEFINED);
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");
        Path out=Paths.get(getScriptArgs()[0]);
        if(Files.exists(out))throw new IllegalArgumentException("Output directory must be new");
        Files.createDirectories(out);Gson json=new Gson();
        bounded(0x40cd64L,0x40cd67L,"factory_lcd_draw_wrapper");
        bounded(0x40ca6cL,0x40cb4fL,"factory_version_draw");
        bounded(0x40cb84L,0x40cc55L,"factory_lcd_draw");
        bounded(0x40cc60L,0x40ccd3L,"factory_grayscale_draw");
        bounded(0x40ccd4L,0x40cd43L,"factory_color_bars_draw");
        Address branch=toAddr(0x40cba4L);Instruction ins=getInstructionAt(branch);
        if(ins==null||!ins.getMnemonicString().equalsIgnoreCase("tbb"))throw new IllegalStateException("Missing measured TBB");
        clearListing(toAddr(0x40cba8L),toAddr(0x40cbafL));
        ArrayList<Address> destinations=new ArrayList<>();ArrayList<Map<String,Object>> states=new ArrayList<>();
        for(int n=0;n<8;n++) {
            int encoded=Byte.toUnsignedInt(getByte(toAddr(0x40cba8L+n)));
            Address target=toAddr(0x40cba8L+2*encoded);destinations.add(target);
            new ArmDisassembleCommand(target,null,true).applyTo(currentProgram,monitor);
            ins.addOperandReference(0,target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
            Map<String,Object> row=new LinkedHashMap<>();row.put("subpage",n+1);
            row.put("table_byte",encoded);row.put("destination",target.toString());states.add(row);
        }
        new JumpTable(branch,destinations,true,0).writeOverride(getFunctionAt(toAddr(0x40cb84L)));
        long[] entries={0x40ca6cL,0x40cb84L,0x40cc60L,0x40ccd4L,0x40cd64L,0x40cd8cL,
            0x4093ccL,0x4164a8L,0x4152dcL,0x408fd0L,0x406364L,0x4087b0L,
            0x409e84L,0x40a5f4L,0x4158e8L,0x40a2a4L,
            0x4047d4L,0x41b940L,0x405834L,0x4058bcL};
        DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);int count=0;
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long at:entries) {
                Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",at));
                Function f=getFunctionAt(toAddr(at));
                if(f==null)row.put("error","No exact entry; no substitution");
                else {
                    DecompileResults r=dec.decompileFunction(f,30,monitor);count++;
                    row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());
                    row.put("error",r.getErrorMessage());row.put("decompiled",r.decompileCompleted()?r.getDecompiledFunction().getC():null);
                }
                w.write(json.toJson(row));w.newLine();
            }
        }finally{dec.dispose();}
        long[][] ranges={{0x40ca6cL,0x40cb4fL},{0x40cb84L,0x40cc55L},
            {0x40cc60L,0x40ccd3L},{0x40ccd4L,0x40cd43L},{0x40cd64L,0x40cd9bL},
            {0x409446L,0x409459L},{0x415370L,0x4155bfL},{0x408fd0L,0x408fe7L},
            {0x4047fcL,0x404821L},{0x41b940L,0x41b96bL}};
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long[] range:ranges) {
                InstructionIterator it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(range[0]),toAddr(range[1])),true);
                while(it.hasNext()) {
                    Instruction i=it.next();Map<String,Object> row=new LinkedHashMap<>();
                    row.put("address",i.getAddress().toString());row.put("instruction",i.toString());
                    StringBuilder hex=new StringBuilder();for(byte b:i.getBytes())hex.append(String.format("%02x",Byte.toUnsignedInt(b)));
                    row.put("bytes",hex.toString());w.write(json.toJson(row));w.newLine();
                }
            }
        }
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);
        meta.put("exact_function_count",count);meta.put("requested_functions",entries.length);
        meta.put("scope","Static repaired factory renderer and selected protocol consumers; no hardware or firmware modification");
        meta.put("factory_switch",states);
        List<Map<String,Object>> translations=new ArrayList<>();
        for(int n=0;n<16;n++) {
            Map<String,Object> row=new LinkedHashMap<>();row.put("native",n);
            row.put("exposed_protocol",Byte.toUnsignedInt(getByte(toAddr(0x408ff8L+n))));
            row.put("detail",Byte.toUnsignedInt(getByte(toAddr(0x408fe8L+n))));translations.add(row);
        }
        meta.put("sc2021_translation",translations);
        Files.writeString(out.resolve("analysis.json"),json.toJson(meta),StandardCharsets.UTF_8);
        println("CUKTECH protocol/factory audit exported "+count+" exact functions; eight measured switch destinations");
    }
}
