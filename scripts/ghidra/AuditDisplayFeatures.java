// Focused static evidence for the AD1204 0073 display/button audit. No device access.
// Run on a read-only project copy; argument is a new absolute output directory.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import com.google.gson.Gson;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Exports the selected display and button feature functions and their original instruction
 * bytes. A missing entry is shown explicitly in the output.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-display-features}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code functions.jsonl}: one row for each requested exact function entry, with body and pseudocode.</li>
 * <li>{@code instructions.jsonl}: the original instruction records and bytes.</li>
 * <li>{@code analysis.json}: image hash, counts and the scope of the evidence.</li>
 * </ul>
 *
 * Program changes: none. It only reads the listing and runs the decompiler.
 * Run it with {@code -readOnly} on a project copy.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output directory already exists.
 */
public class AuditDisplayFeatures extends GhidraScript {
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))
            throw new IllegalArgumentException("Only the measured AD1204 0073 raw image is supported.");
        Path out=Paths.get(getScriptArgs()[0]);
        if(Files.exists(out))throw new IllegalArgumentException("Output directory must be new");
        Files.createDirectories(out);
        Gson json=new Gson();
        DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);
        long[] seeds={0x4047ccL,0x4048d4L,0x4049fcL,0x404b64L,0x404b80L,0x404d2cL,
            0x405f0cL,0x406044L,0x4060c8L,0x406164L,0x4061a4L,0x4061c6L,0x4061fcL,
            0x40627cL,0x4062dcL,0x406474L,0x406528L,0x406560L,0x4065a8L,0x406adcL,
            0x4069ccL,0x409b10L,0x409ba4L,0x40bcb8L,0x40cda4L,0x40d07cL,
            0x40d2e0L,0x40d8c0L,0x40da74L,0x40e1dcL,0x40ef9cL,0x40f178L,
            0x40faecL,0x411208L,0x4112e0L,0x4113a4L,0x411660L,0x417da4L,
            0x413738L,0x413774L,0x4220fcL,0x415e10L,0x417c24L,0x41d03cL,0x41cf88L};
        Set<Address> done=new HashSet<>();int count=0;
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long entry:seeds) {
                Function f=getFunctionAt(toAddr(entry));
                Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",entry));
                if(f==null){row.put("error","No function at exact address; no containing-function substitution");}
                else {
                    if(!done.add(f.getEntryPoint()))continue;
                    DecompileResults result=dec.decompileFunction(f,30,monitor);
                    row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());
                    row.put("error",result.getErrorMessage());
                    row.put("decompiled",result.decompileCompleted()?result.getDecompiledFunction().getC():null);
                    count++;
                }
                w.write(json.toJson(row));w.newLine();
            }
        }finally{dec.dispose();}
        long[][] ranges={{0x417da4L,0x417e13L},{0x413738L,0x41374fL},{0x413774L,0x41378bL},
            {0x4042d8L,0x4042f5L},{0x421852L,0x42185bL},{0x4220fcL,0x422127L},
            {0x4048d4L,0x404913L},{0x40bcb8L,0x40be23L},{0x406528L,0x40655fL},
            {0x415e10L,0x415e4bL},{0x417c24L,0x417c4dL},{0x41d03cL,0x41d059L},
            {0x41cf88L,0x41d017L}};
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long[] range:ranges) {
                InstructionIterator it=currentProgram.getListing().getInstructions(new AddressSet(toAddr(range[0]),toAddr(range[1])),true);
                while(it.hasNext()) {
                    Instruction i=it.next();Map<String,Object> row=new LinkedHashMap<>();
                    row.put("address",i.getAddress().toString());row.put("instruction",i.toString());
                    byte[] bytes=i.getBytes();StringBuilder hex=new StringBuilder();
                    for(byte b:bytes)hex.append(String.format("%02x",Byte.toUnsignedInt(b)));
                    row.put("bytes",hex.toString());w.write(json.toJson(row));w.newLine();
                }
            }
        }
        Map<String,Object> metadata=new LinkedHashMap<>();metadata.put("sha256",sha);
        metadata.put("exact_function_count",count);metadata.put("requested_functions",seeds.length);
        metadata.put("scope","Static selected functions/instructions; merged decompiler bodies require assembly review; no runtime/hardware evidence.");
        Files.writeString(out.resolve("analysis.json"),json.toJson(metadata),StandardCharsets.UTF_8);
        println("CUKTECH display audit exported "+count+" exact functions to "+out);
    }
}
