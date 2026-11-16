// Retain selected ADC, optional DFU and factory-screen evidence without device access.
// Argument: a new absolute output directory. Use -readOnly -noanalysis.
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
 * Exports the selected ADC, optional DFU and factory-screen functions and their instructions.
 * It exports only exact entries. It does not use the function that contains an address instead.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/audit-coverage-gaps}</li>
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
public class AuditCoverageGaps extends GhidraScript {
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))
            throw new IllegalArgumentException("Only the measured AD1204 0073 raw image is supported");
        Path out=Paths.get(getScriptArgs()[0]);
        if(Files.exists(out))throw new IllegalArgumentException("Output directory must be new");
        Files.createDirectories(out);
        Gson json=new Gson();
        long[] seeds={0x415028L,0x412408L,0x41216cL,0x4122c8L,0x4120fcL,0x4124c4L,
            0x41382cL,0x41390cL,0x41fdc4L,0x41ae44L,0x41b3f0L,0x41b7ecL,
            0x406354L,0x40a718L,0x4164a8L,0x41f8f8L,0x40fe6cL,0x417ba4L};
        DecompInterface dec=new DecompInterface();dec.openProgram(currentProgram);int count=0;
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8)) {
            for(long entry:seeds) {
                Function f=getFunctionAt(toAddr(entry));
                Map<String,Object> row=new LinkedHashMap<>();row.put("requested_address",String.format("%08x",entry));
                if(f==null)row.put("error","No exact function; no containing-function substitution");
                else {
                    DecompileResults result=dec.decompileFunction(f,30,monitor);
                    row.put("address",f.getEntryPoint().toString());row.put("body",f.getBody().toString());
                    row.put("error",result.getErrorMessage());
                    row.put("decompiled",result.decompileCompleted()?result.getDecompiledFunction().getC():null);count++;
                }
                w.write(json.toJson(row));w.newLine();
            }
        }finally{dec.dispose();}
        long[][] ranges={{0x41216cL,0x412200L},{0x412408L,0x4124b2L},
            {0x40520cL,0x405215L},{0x4054a4L,0x4054a9L},{0x40557aL,0x40557fL},
            {0x41b006L,0x41b03fL},{0x40632aL,0x406353L},{0x40a778L,0x40a7c7L},
            {0x4164a8L,0x4164d7L},{0x40fe6cL,0x40fef7L}};
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
        Map<String,Object> metadata=new LinkedHashMap<>();metadata.put("sha256",sha);
        metadata.put("exact_function_count",count);metadata.put("requested_functions",seeds.length);
        metadata.put("scope","Retained static selection only; no semantic completion or hardware validation count");
        Files.writeString(out.resolve("analysis.json"),json.toJson(metadata),StandardCharsets.UTF_8);
        println("CUKTECH gap audit exported "+count+" exact functions to "+out);
    }
}
