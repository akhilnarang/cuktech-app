// Reconstruct measured startup copy/expand regions from firmware_unpack output.
// Argument: absolute path to unpacked manifest.json. Run on the imported raw image.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.Address;
import com.google.gson.*;
import java.nio.file.*;
import java.io.*;
import java.math.BigInteger;
import java.util.*;

/**
 * Reconstructs the measured startup copy and expand regions in the program, from the output of
 * the firmware unpacker. For each region that is not zero-fill, it creates or fills an
 * initialized block {@code startup_<kind>_<address>} with the expanded bytes and sets TMode.
 * It then creates functions at Thumb pointers that point to a PUSH prologue in an executable
 * block, adds the seed 0x002013bc and runs auto-analysis again.
 *
 * Arguments:
 * <ol>
 * <li>manifest: absolute path to the unpacked {@code manifest.json}. The region files must be in the
 * same directory. Example: {@code artifacts/firmware/reproduced-0073/unpacked/manifest.json}</li>
 * </ol>
 *
 * Output: progress lines in the script console.
 *
 * Program changes: memory blocks, block bytes, context, functions and analysis. Run it on the
 * imported raw image.
 *
 * It stops with an exception if the manifest hash differs from the program hash, if a region
 * file has the wrong size, or if a target block is already initialized.
 */
public class ReconstructChargerMemory extends GhidraScript {
    public void run() throws Exception {
        Path manifestPath=Paths.get(getScriptArgs()[0]);
        JsonObject manifest=JsonParser.parseString(Files.readString(manifestPath)).getAsJsonObject();
        String expected=manifest.getAsJsonArray("outputs").get(0).getAsJsonObject().get("sha256").getAsString();
        if(!expected.equals(currentProgram.getExecutableSHA256()))throw new IOException("Manifest payload differs from imported raw firmware");
        Memory memory=currentProgram.getMemory();
        List<MemoryBlock> reconstructed=new ArrayList<>();
        for(JsonElement element:manifest.getAsJsonArray("startup_regions")) {
            JsonObject row=element.getAsJsonObject();
            String kind=row.get("kind").getAsString();
            if(kind.equals("zero_fill"))continue; // BSS remains uninitialized in the static model.
            long destination=row.get("destination_address").getAsLong();
            long size=row.get("expanded_size").getAsLong();
            Address start=toAddr(destination);
            byte[] bytes=Files.readAllBytes(manifestPath.getParent().resolve(row.get("file").getAsString()));
            if(bytes.length!=size)throw new IOException("Reconstruction size mismatch");
            MemoryBlock block=memory.getBlock(start);
            if(block==null) {
                block=memory.createInitializedBlock("startup_"+kind+"_"+start,start,new ByteArrayInputStream(bytes),size,monitor,false);
            } else {
                if(block.isInitialized())throw new IOException("Refusing to overwrite initialized memory at "+start);
                if(!block.getStart().equals(start)){memory.split(block,start);block=memory.getBlock(start);}
                Address after=start.add(size);
                if(after.compareTo(block.getEnd())<=0)memory.split(block,after);
                block=memory.convertToInitialized(block,(byte)0);
                memory.setBytes(start,bytes);
                block.setName("startup_"+kind+"_"+start);
            }
            block.setRead(true);block.setWrite(true);block.setExecute(kind.equals("copy")&&destination>=0x200140&&destination<0x201724);
            currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),block.getStart(),block.getEnd(),BigInteger.ONE);
            reconstructed.add(block);
            println("CUKTECH reconstructed "+kind+" "+start+" size "+size);
        }
        // Pointer targets from both flash and reconstructed data can now resolve
        // into code that previously existed only in its load-address copy.
        TreeSet<Long> seeds=new TreeSet<>();
        for(MemoryBlock block:memory.getBlocks()) {
            if(!block.isInitialized())continue;
            for(long at=block.getStart().getOffset();at+4<=block.getEnd().getOffset();at+=4) {
                long ptr=Integer.toUnsignedLong(getInt(toAddr(at))),target=ptr&~1L;
                MemoryBlock targetBlock=memory.getBlock(toAddr(target));
                if((ptr&1)==0||targetBlock==null||!targetBlock.isExecute()||!targetBlock.isInitialized())continue;
                if(target+4>targetBlock.getEnd().getOffset())continue;
                int h=Short.toUnsignedInt(getShort(toAddr(target)));
                if((h&0xff00)==0xb500||h==0xe92d)seeds.add(target);
            }
        }
        seeds.add(0x2013bcL);
        for(long value:seeds){Address address=toAddr(value);disassemble(address);if(getFunctionAt(address)==null)createFunction(address,null);}
        analyzeAll(currentProgram);
        println("CUKTECH reconstructed-memory analysis complete");
    }
}
