// Original 0073 RGB565 renderer, synthetic SRAM viewport/framebuffer only.
// Args: firmware_bitmaps manifest.json; new absolute verification directory.
// No LCD, peripheral, BLE or ROM operation is executed. Use -readOnly.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;

/**
 * Checks the original uncropped opaque RGB565 renderer and the framebuffer-address helper. It
 * renders each bitmap from the manifest into a synthetic framebuffer and compares the result with
 * the decoded file. It also runs three synthetic encodings. No LCD code runs.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>manifest: path to the {@code manifest.json} of firmware_bitmaps. The
 * {@code bitmap-<address>.rgb565-le.bin} files must be in the same directory.
 * Example: {@code artifacts/firmware/bitmaps-0073/manifest.json}</li>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-color-bitmaps}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code cases.jsonl}: one row for each synthetic case, with inputs and observed results.</li>
 * <li>{@code executed-instructions.jsonl}: each distinct original instruction that ran, with its bytes.</li>
 * <li>{@code verification.json}: image hash, counts, stops and the scope of the check.</li>
 * </ul>
 *
 * Program changes: none. All writes go to the emulator state only.
 * Run it on a read-only project copy.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output directory already exists. It stops with an exception if an observed result differs from the expected result.
 */
public class VerifyColorBitmaps extends GhidraScript {
    private long totalSteps,modeCallbacks;
    private final TreeSet<Long> visited=new TreeSet<>();
    private String digest(byte[] bytes) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    @SuppressWarnings("unchecked")
    private void fixedThumbWorkaround(EmulatorHelper helper) throws Exception {
        var outer=helper.getEmulator().getClass().getDeclaredField("emulator");outer.setAccessible(true);
        Emulate engine=(Emulate)outer.get(helper.getEmulator());
        var field=Emulate.class.getDeclaredField("instructionStateModifier");field.setAccessible(true);
        var modifier=(EmulateInstructionStateModifier)field.get(engine);
        var mapping=EmulateInstructionStateModifier.class.getDeclaredField("pcodeOpMap");mapping.setAccessible(true);
        Map<Integer,OpBehaviorOther> operations=(Map<Integer,OpBehaviorOther>)mapping.get(modifier);boolean replaced=false;
        for(int index:new ArrayList<>(operations.keySet())) {
            if(!"setISAMode".equals(currentProgram.getLanguage().getUserDefinedOpName(index)))continue;
            operations.put(index,(emulate,output,inputs)-> {
                if(emulate.getMemoryState().getValue(currentProgram.getRegister("ISAModeSwitch"))!=1)throw new IllegalStateException("Unexpected ARM-mode transition");
                long pc=emulate.getExecuteAddress().getOffset();if((pc&1)!=0)emulate.setExecuteAddress(toAddr(pc&~1L));modeCallbacks++;
            });replaced=true;
        }
        if(!replaced)throw new IllegalStateException("Expected ARM handler not found");
    }
    private Map<String,Object> render(String name,long descriptor,int width,int height,byte[] expected,byte[] syntheticDescriptor,byte[] syntheticSource) throws Exception {
        int size=width*height*2;if(size!=expected.length||width<1||height<1||width>320||height>320)throw new IllegalArgumentException("Bad bitmap fixture");
        long context=0x20010000L,viewport=0x20010100L,buffer=0x20020000L,stack=0x20078000L;
        byte[] guard=new byte[16];Arrays.fill(guard,(byte)0xa5);
        EmulatorHelper emu=new EmulatorHelper(currentProgram);long steps=0;
        try {
            fixedThumbWorkaround(emu);
            for(int n=0;n<13;n++)emu.writeRegister("r"+n,0);
            emu.writeRegister("sp",stack);emu.writeRegister("lr",0x40306bL);
            emu.writeMemory(toAddr(context),new byte[32]);emu.writeMemory(toAddr(viewport),new byte[32]);
            emu.writeMemoryValue(toAddr(context+8),4,viewport);
            emu.writeMemoryValue(toAddr(viewport+8),2,width);emu.writeMemoryValue(toAddr(viewport+10),2,height);
            emu.writeMemoryValue(toAddr(viewport+24),4,buffer);emu.writeMemoryValue(toAddr(stack),4,0);
            emu.writeMemory(toAddr(buffer-16),guard);emu.writeMemory(toAddr(buffer+size),guard);
            byte[] initial=new byte[size];Arrays.fill(initial,(byte)0xcd);emu.writeMemory(toAddr(buffer),initial);
            if(syntheticDescriptor!=null) {
                emu.writeMemory(toAddr(descriptor),syntheticDescriptor);emu.writeMemory(toAddr(0x20010300L),syntheticSource);
            }
            emu.writeRegister("r1",context);emu.writeRegister("r2",descriptor);emu.writeRegister("r3",0);
            emu.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);
            emu.writeRegister(emu.getPCRegister(),0x40e30cL);
            while(!emu.getExecutionAddress().equals(toAddr(0x40e32aL))) {
                monitor.checkCancelled();long pc=emu.getExecutionAddress().getOffset();
                if(!((pc>=0x40e30cL&&pc<=0x40e451L)||(pc>=0x41183cL&&pc<=0x411841L)||(pc>=0x4114b6L&&pc<=0x4114edL)))throw new IllegalStateException("Escaped renderer: "+Long.toHexString(pc));
                if(++steps>3000000)throw new IllegalStateException("Bitmap instruction budget exceeded");visited.add(pc);
                if(!emu.step(monitor))throw new IllegalStateException(emu.getLastError());
            }
            byte[] actual=emu.readMemory(toAddr(buffer),size);
            for(int i=0;i<size;i+=2) {byte swap=actual[i];actual[i]=actual[i+1];actual[i+1]=swap;}
            if(!Arrays.equals(actual,expected))throw new IllegalStateException("Renderer output mismatch: "+name);
            if(!Arrays.equals(guard,emu.readMemory(toAddr(buffer-16),16))||!Arrays.equals(guard,emu.readMemory(toAddr(buffer+size),16)))throw new IllegalStateException("Framebuffer guard changed");
            totalSteps+=steps;Map<String,Object> row=new LinkedHashMap<>();row.put("case",name);row.put("descriptor",String.format("%08x",descriptor));
            row.put("width",width);row.put("height",height);row.put("decoded_rgb565_sha256",digest(actual));row.put("expected_sha256",digest(expected));
            row.put("instruction_steps",steps);row.put("matches",true);row.put("guards_intact",true);return row;
        }finally{emu.dispose();}
    }
    private byte[] synthetic(int width,int height,int marker) {
        return new byte[]{(byte)width,(byte)(width>>8),(byte)height,(byte)(height>>8),16,0,(byte)marker,0,0,3,1,32};
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        Path manifest=Paths.get(getScriptArgs()[0]),out=Paths.get(getScriptArgs()[1]);
        if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        JsonObject input=JsonParser.parseString(Files.readString(manifest,StandardCharsets.UTF_8)).getAsJsonObject();
        if(!sha.equals(input.get("sha256").getAsString()))throw new IllegalArgumentException("Manifest identity mismatch");
        Files.createDirectories(out);Gson json=new Gson();int count=0;
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)) {
            for(JsonElement element:input.getAsJsonArray("bitmaps")) {
                JsonObject record=element.getAsJsonObject();String filename=record.get("rgb565_file").getAsString();
                if(!filename.matches("bitmap-[0-9a-f]{8}\\.rgb565-le\\.bin"))throw new IllegalArgumentException("Unexpected fixture filename");
                byte[] expected=Files.readAllBytes(manifest.getParent().resolve(filename));
                if(!digest(expected).equals(record.get("decoded_sha256").getAsString()))throw new IllegalStateException("Fixture hash mismatch");
                Map<String,Object> row=render(filename,record.get("descriptor_address").getAsLong(),record.get("width").getAsInt(),record.get("height").getAsInt(),expected,null,null);
                w.write(json.toJson(row));w.newLine();count++;
            }
            byte[][] encoded={HexFormat.of().parseHex("00f8e0071f00"),HexFormat.of().parseHex("000600f8"),HexFormat.of().parseHex("00f80301e0071f00")};
            byte[][] expected={encoded[0],new byte[512],HexFormat.of().parseHex("00f8e007e007e0071f00")};
            for(int n=0;n<256;n++){expected[1][2*n]=0;expected[1][2*n+1]=(byte)0xf8;}
            int[] widths={3,256,5},markers={0,6,1};
            for(int n=0;n<3;n++) {Map<String,Object> row=render("synthetic-"+n,0x20010200L,widths[n],1,expected[n],synthetic(widths[n],1,markers[n]),encoded[n]);w.write(json.toJson(row));w.newLine();count++;}
        }
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long pc:visited) {var ins=getInstructionAt(toAddr(pc));if(ins==null)throw new IllegalStateException("No retained instruction at "+Long.toHexString(pc));
                Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}
        }
        Map<String,Object> result=new LinkedHashMap<>();result.put("sha256",sha);result.put("manifest_sha256",digest(Files.readAllBytes(manifest)));
        result.put("cases",count);result.put("instruction_steps",totalSteps);result.put("mode_callbacks",modeCallbacks);result.put("all_outputs_match",true);
        result.put("scope","Original uncropped opaque RGB565 renderer and pure framebuffer-address helper; synthetic SRAM viewport/buffer, all exported bitmap fixtures plus literal/mixed/zero-count cases. No LCD, ROM or peripheral execution. Color-key transparency and clipping outside this check.");
        result.put("emulator_workaround","Instance-local fixed-Thumb setISAMode replacement, as documented for prior ADC/thermal verifiers; rejects ARM transitions, preserves original instruction p-code.");
        result.put("stop_boundary","Before outer POP PC at0040e32a; each complete framebuffer and both16-byte guards checked");
        Files.writeString(out.resolve("verification.json"),json.toJson(result),StandardCharsets.UTF_8);
        println("CUKTECH RGB565 renderer verified: "+count+" fixtures; "+totalSteps+" instructions");
    }
}
