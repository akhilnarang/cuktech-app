// Export analysis observations and decompiler output without executing firmware.
// Argument: absolute output directory. Run after Ghidra auto-analysis.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

/**
 * Exports the analysis results and the decompiler output. It does not run firmware code. Run it
 * after Ghidra auto-analysis. The decompiler timeout is 30 s for each function.
 *
 * Arguments:
 * <ol>
 * <li>output directory: absolute path. The script creates it if necessary and overwrites the files.
 * Example: {@code artifacts/firmware/reproduced-0073/analysis}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code functions.jsonl}: each function with body, signature, pseudocode, callers and references.</li>
 * <li>{@code decompiled.c}: all pseudocode in one file. It is not original or compilable source.</li>
 * <li>{@code strings.jsonl}: each defined string and its references.</li>
 * <li>{@code analysis.json}: program hash, language, counts, memory blocks and limits.</li>
 * </ul>
 *
 * Program changes: none.
 */
public class ExportChargerFirmware extends GhidraScript {
    private final Gson json = new GsonBuilder().disableHtmlEscaping().create();
    private List<Map<String,Object>> references(ReferenceIterator refs) {
        List<Map<String,Object>> result = new ArrayList<>();
        while (refs.hasNext()) {
            Reference r = refs.next();
            Map<String,Object> row = new LinkedHashMap<>();
            row.put("from",r.getFromAddress().toString());
            row.put("to",r.getToAddress().toString());
            row.put("type",r.getReferenceType().toString());
            Function caller = getFunctionContaining(r.getFromAddress());
            row.put("function",caller==null?null:caller.getEntryPoint().toString());
            result.add(row);
        }
        return result;
    }
    public void run() throws Exception {
        Path out = Paths.get(getScriptArgs()[0]);
        Files.createDirectories(out);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int count=0, complete=0;
        try (BufferedWriter functions=Files.newBufferedWriter(out.resolve("functions.jsonl"),StandardCharsets.UTF_8);
             BufferedWriter c=Files.newBufferedWriter(out.resolve("decompiled.c"),StandardCharsets.UTF_8);
             BufferedWriter strings=Files.newBufferedWriter(out.resolve("strings.jsonl"),StandardCharsets.UTF_8)) {
            FunctionIterator iterator=currentProgram.getFunctionManager().getFunctions(true);
            while(iterator.hasNext()) {
                monitor.checkCancelled();
                Function f=iterator.next();
                if(f.isExternal()) continue;
                DecompileResults d=decompiler.decompileFunction(f,30,monitor);
                String source=d.decompileCompleted()&&d.getDecompiledFunction()!=null?d.getDecompiledFunction().getC():null;
                if(source!=null)complete++;
                Map<String,Object> row=new LinkedHashMap<>();
                row.put("address",f.getEntryPoint().toString());row.put("name",f.getName());
                row.put("body",f.getBody().toString());row.put("signature",f.getSignature().toString());
                row.put("decompiled",source);row.put("error",d.getErrorMessage());
                row.put("callers",references(currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint())));
                List<Map<String,Object>> outgoing=new ArrayList<>();
                InstructionIterator instructions=currentProgram.getListing().getInstructions(f.getBody(),true);
                while(instructions.hasNext()) {
                    Instruction ins=instructions.next();
                    for(Reference r:ins.getReferencesFrom()) {
                        if(r.getReferenceType().isCall()||r.getReferenceType().isData()) {
                            Map<String,Object> ref=new LinkedHashMap<>();
                            ref.put("from",ins.getAddress().toString());ref.put("to",r.getToAddress().toString());
                            ref.put("type",r.getReferenceType().toString());outgoing.add(ref);
                        }
                    }
                }
                row.put("references",outgoing);functions.write(json.toJson(row));functions.newLine();
                c.write("\n/* "+f.getEntryPoint()+" "+f.getName()+" */\n");
                c.write(source==null?"/* Decompilation unavailable: "+d.getErrorMessage()+" */\n":source);
                count++;
                if(count%200==0)println("CUKTECH exported "+count+" functions");
            }
            DataIterator data=currentProgram.getListing().getDefinedData(true);
            while(data.hasNext()) {
                Data item=data.next();
                if(!(item.getValue() instanceof String))continue;
                Map<String,Object> row=new LinkedHashMap<>();
                row.put("address",item.getAddress().toString());row.put("value",item.getValue());
                row.put("references",references(currentProgram.getReferenceManager().getReferencesTo(item.getAddress())));
                strings.write(json.toJson(row));strings.newLine();
            }
        } finally {decompiler.dispose();}
        Map<String,Object> metadata=new LinkedHashMap<>();
        metadata.put("program",currentProgram.getName());metadata.put("sha256",currentProgram.getExecutableSHA256());
        metadata.put("language",currentProgram.getLanguageID().toString());metadata.put("image_base",currentProgram.getImageBase().toString());
        metadata.put("function_count",count);metadata.put("decompiled_count",complete);
        List<Map<String,Object>> blocks=new ArrayList<>();
        for(ghidra.program.model.mem.MemoryBlock block:currentProgram.getMemory().getBlocks()) {
            Map<String,Object> row=new LinkedHashMap<>();
            row.put("name",block.getName());row.put("start",block.getStart().toString());row.put("end",block.getEnd().toString());
            row.put("initialized",block.isInitialized());row.put("execute",block.isExecute());row.put("write",block.isWrite());blocks.add(row);
        }
        metadata.put("memory_blocks",blocks);
        metadata.put("limitations",Arrays.asList("Static decompiler observations, not original source or observed execution.",
            "Flash load address comes from the R2SF header. Startup copy/expanded regions are reconstructed when their named memory blocks exist; other SRAM coverage remains synthetic and uninitialized.",
            "Automatic function discovery and indirect call recovery are incomplete; data may be misclassified as code."));
        Files.writeString(out.resolve("analysis.json"),json.toJson(metadata),StandardCharsets.UTF_8);
        println("CUKTECH complete: "+complete+" / "+count+" functions decompiled");
    }
}
