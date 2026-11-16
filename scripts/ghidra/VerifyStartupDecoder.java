// Independently compare the Python reconstruction with original Thumb instructions.
// Only the pure memory-to-memory decompressor is emulated; no hardware or ROM call.
// Args: expected expanded .bin, output verification .json.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import java.nio.file.*;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.util.*;
import com.google.gson.GsonBuilder;

/**
 * Compares the Python reconstruction of the startup block with the original Thumb decompressor.
 * It emulates only the memory-to-memory decompressor at 0x00403b40, from source 0x00477c08 to
 * 0x20001730. It stops at 0x00403b9c, before the return epilogue: the ARM mode-switch userop of
 * that return gives an emulator context-state error in this Ghidra release.
 *
 * Arguments:
 * <ol>
 * <li>expected block: path to the expanded .bin from the Python unpacker (0xaec8 bytes).</li>
 * <li>output file: path of the verification JSON file. The script overwrites it.
 * Example: {@code artifacts/firmware/reproduced-0073/analysis/decoder-verification.json}</li>
 * </ol>
 *
 * Output: a JSON file with addresses, consumed bytes, steps, match result, guard result and the
 * expanded SHA-256.
 *
 * Program changes: none. All writes go to the emulator state only.
 *
 * It stops with an exception if the expected block has the wrong size, if the output differs, if
 * a guard byte changes or if the decoder does not consume 17434 source bytes. It writes the JSON
 * file before this check.
 */
public class VerifyStartupDecoder extends GhidraScript {
    public void run() throws Exception {
        byte[] expected=Files.readAllBytes(Paths.get(getScriptArgs()[0]));
        if(expected.length!=0xaec8)throw new IllegalArgumentException("Expected measured 0073 expanded block");
        EmulatorHelper emulator=new EmulatorHelper(currentProgram);
        try {
            byte[] poisoned=new byte[expected.length];Arrays.fill(poisoned,(byte)0xe5);
            emulator.writeMemory(toAddr(0x20001730L),poisoned);
            emulator.writeMemory(toAddr(0x2000172fL),new byte[]{(byte)0xcc});
            emulator.writeMemory(toAddr(0x2000c5f8L),new byte[]{(byte)0xdd});
            emulator.writeRegister("r0",0x477c08L);
            emulator.writeRegister("r1",0x20001730L);
            emulator.writeRegister("r2",expected.length);
            emulator.writeRegister("r4",0);emulator.writeRegister("r5",0);emulator.writeRegister("r6",0);
            emulator.writeRegister("sp",0x2007ff00L);
            emulator.writeRegister("lr",0x40306bL);
            emulator.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);
            emulator.writeRegister(emulator.getPCRegister(),0x403b40L);
            int steps=0;long consumed=-1;
            // Stop before POP {...,pc}: its ARM mode-switch userop triggers an
            // EmulatorHelper context-state error in this Ghidra release. Output
            // is already complete and r0 has been set to success at this point.
            while(!emulator.getExecutionAddress().equals(toAddr(0x403b9cL))) {
                monitor.checkCancelled();
                long pc=emulator.getExecutionAddress().getOffset();
                if(pc<0x403b40L||pc>0x403b9cL)throw new IllegalStateException("Emulator escaped decompressor: "+Long.toHexString(pc));
                if(pc==0x403b9aL)consumed=emulator.readRegister("r0").longValue()-0x477c08L;
                if(++steps>1000000)throw new IllegalStateException("Instruction budget exceeded");
                if(!emulator.step(monitor))throw new IllegalStateException(emulator.getLastError());
            }
            byte[] observed=emulator.readMemory(toAddr(0x20001730L),expected.length);
            boolean equal=Arrays.equals(observed,expected);
            boolean guards=emulator.readMemoryByte(toAddr(0x2000172fL))==(byte)0xcc&&emulator.readMemoryByte(toAddr(0x2000c5f8L))==(byte)0xdd;
            Map<String,Object> result=new LinkedHashMap<>();
            result.put("decoder_entry","00403b40");result.put("source_address","00477c08");
            result.put("destination_address","20001730");result.put("expanded_bytes",observed.length);
            result.put("source_bytes_consumed",consumed);result.put("instruction_steps",steps);
            result.put("python_matches_original_thumb",equal);result.put("output_guards_intact",guards);
            result.put("stop_address","00403b9c (before return epilogue)");
            result.put("expanded_sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(observed)));
            result.put("scope","Offline instruction emulation of this decompressor only; not observed charger execution.");
            Files.writeString(Paths.get(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().create().toJson(result));
            println("CUKTECH decoder emulation: "+equal+", guards "+guards+", "+steps+" instructions, consumed "+consumed);
            if(!equal||!guards||consumed!=17434)throw new IllegalStateException("Decoder verification failed");
        } finally {emulator.dispose();}
    }
}
