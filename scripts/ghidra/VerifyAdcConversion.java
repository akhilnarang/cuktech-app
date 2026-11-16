// Offline emulation of the original channel-zero ADC conversion, not acquisition.
// No peripheral, BLE, ROM, calibration write or charger command is executed.
// Args: new absolute output directory; optional --aliases-only for 0x24 cases.
// Use a read-only 0073 project copy.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.Gson;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.OpBehaviorOther;

/**
 * Checks the original channel-zero ADC conversion with synthetic scaled samples and calibration
 * words. It does not read the ADC. It does not show physical Celsius accuracy.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-adc}</li>
 * <li>{@code --aliases-only} (optional): run only the 0x24 low-byte alias cases.</li>
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
public class VerifyAdcConversion extends GhidraScript {
    private long instructionSteps;
    private long modeCallbacks;
    private final TreeSet<Long> visited = new TreeSet<>();
    private void writeInt(EmulatorHelper emu,long address,int value) {
        emu.writeMemory(toAddr(address),new byte[]{(byte)value,(byte)(value>>8),(byte)(value>>16),(byte)(value>>24)});
    }
    @SuppressWarnings("unchecked")
    private void fixedThumbWorkaround(EmulatorHelper helper) throws Exception {
        // Ghidra 12.1.4's ARM setISAMode handler attempts a context update while
        // RUNNING, which throws even on a Thumb-to-Thumb BL. Replace only this
        // handler in this emulator instance; keep all original instruction p-code.
        // This workaround is deliberately invalid for any transition to ARM.
        var outer=helper.getEmulator().getClass().getDeclaredField("emulator");outer.setAccessible(true);
        Emulate engine=(Emulate)outer.get(helper.getEmulator());
        var field=Emulate.class.getDeclaredField("instructionStateModifier");field.setAccessible(true);
        var modifier=(EmulateInstructionStateModifier)field.get(engine);
        var mapping=EmulateInstructionStateModifier.class.getDeclaredField("pcodeOpMap");mapping.setAccessible(true);
        Map<Integer,OpBehaviorOther> operations=(Map<Integer,OpBehaviorOther>)mapping.get(modifier);boolean replaced=false;
        for(int index:new ArrayList<>(operations.keySet())) {
            if(!"setISAMode".equals(currentProgram.getLanguage().getUserDefinedOpName(index)))continue;
            operations.put(index,(emulate,output,inputs)-> {
                long mode=emulate.getMemoryState().getValue(currentProgram.getRegister("ISAModeSwitch"));
                if(mode!=1)throw new IllegalStateException("Unexpected ARM-mode transition");
                long address=emulate.getExecuteAddress().getOffset();
                if((address&1)!=0)emulate.setExecuteAddress(toAddr(address&~1L));
                modeCallbacks++;
            });replaced=true;
        }
        if(!replaced)throw new IllegalStateException("Expected Ghidra ARM handler not found");
    }
    private int convert(int sample,int reference,boolean fallback) throws Exception {
        EmulatorHelper emu=new EmulatorHelper(currentProgram);
        try {
            fixedThumbWorkaround(emu);
            writeInt(emu,0x2000c27cL,fallback?0x1fffffff:reference);
            writeInt(emu,0x2000d2e4L,reference);
            emu.writeRegister("r0",0);emu.writeRegister("r1",sample);
            for(String register:new String[]{"r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12"})emu.writeRegister(register,0);
            emu.writeRegister("sp",0x20047000L);emu.writeRegister("lr",0x40306bL);
            emu.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);
            emu.writeRegister(emu.getPCRegister(),0x41216cL);
            int steps=0;
            while(!emu.getExecutionAddress().equals(toAddr(0x412200L))) {
                monitor.checkCancelled();long pc=emu.getExecutionAddress().getOffset();
                boolean allowed=(pc>=0x41216cL&&pc<0x412200L)||(pc>=0x403000L&&pc<0x403b00L)
                    ||(pc>=0x40520cL&&pc<=0x405214L)||(pc>=0x4054a4L&&pc<=0x4054a8L)
                    ||(pc>=0x40557aL&&pc<=0x40557eL);
                if(!allowed)throw new IllegalStateException("Escaped arithmetic: "+Long.toHexString(pc));
                if(++steps>20000)throw new IllegalStateException("Arithmetic budget exceeded");
                visited.add(pc);
                if(!emu.step(monitor))throw new IllegalStateException("Emulator at "+Long.toHexString(pc)+": "+emu.getLastError());
            }
            instructionSteps+=steps;
            return emu.readRegister("r0").intValue();
        }finally{emu.dispose();}
    }
    private int model(int sample,int reference) {
        float delta=(float)reference-(float)sample;
        double value=(double)delta*(1.0/2048.0);
        value=value*1000.0;
        value=value/1.824;
        value=value+25.0;
        return (int)(float)value;
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        Path out=Paths.get(getScriptArgs()[0]);
        boolean aliasesOnly=getScriptArgs().length==2&&"--aliases-only".equals(getScriptArgs()[1]);
        if(getScriptArgs().length>2||(getScriptArgs().length==2&&!aliasesOnly))throw new IllegalArgumentException("Unknown fixture selection");
        if(Files.exists(out))throw new IllegalArgumentException("Output directory must be new");
        Files.createDirectories(out);Gson json=new Gson();int total=0;
        int[] references=aliasesOnly?new int[]{1394}:new int[]{1394,1200,1600};
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)) {
            for(int reference:references)for(boolean fallback:new boolean[]{false,true}) {
                TreeSet<Integer> samples=new TreeSet<>();
                if(aliasesOnly)samples.addAll(Arrays.asList(393,396,1350,1352,2310,2312,3266,3269));
                else {
                    for(int value=0;value<=4095;value+=64)samples.add(value);
                    for(int delta:new int[]{-1024,-100,-43,-42,-41,-4,-1,0,1,4,93,94,95,100,1024})samples.add(reference+delta);
                    samples.addAll(Arrays.asList(-32768,-1,0,1,4095,32767));
                }
                for(int sample:samples) {
                    int expected=model(sample,reference),actual=convert(sample,reference,fallback);
                    Map<String,Object> row=new LinkedHashMap<>();row.put("reference",reference);row.put("sentinel_fallback",fallback);
                    row.put("scaled_sample",sample);row.put("expected",expected);row.put("observed",actual);
                    row.put("vendor_low_byte",actual&255);w.write(json.toJson(row));w.newLine();
                    if(actual!=expected)throw new IllegalStateException("Conversion mismatch: "+json.toJson(row));total++;
                }
            }
        }
        Map<String,Object> result=new LinkedHashMap<>();result.put("sha256",sha);result.put("entry","0041216c");
        result.put("cases",total);result.put("instruction_steps",instructionSteps);result.put("all_expected_results_match",true);
        result.put("mode_callbacks",modeCallbacks);
        if(aliasesOnly)result.put("fixture_set","0x24 low-byte aliases; eight scaled samples with reference1394, direct and sentinel-fallback paths");
        result.put("emulator_workaround","Instance-local replacement of Ghidra 12.1.4 setISAMode callback: assert Thumb, align odd PC, retain existing Thumb context. Original instruction p-code and arithmetic helpers execute unchanged. No ARM-mode transition allowed; no installed Ghidra or firmware bytes modified.");
        result.put("stop_boundary","Before outer POP PC at 00412200; original arithmetic helpers are executed");
        result.put("scope","Synthetic scaled samples and calibration words only. No ADC acquisition, peripheral or ROM execution. Does not establish physical Celsius accuracy or actual owner calibration/sample.");
        result.put("model","float delta=float(reference)-float(sample); double v=double(delta)/2048; v*=1000; v/=1.824; v+=25; return int(float(v)); vendor byte=result&255");
        ArrayList<Map<String,Object>> windows=new ArrayList<>();
        for(long[] range:new long[][]{{0x41216cL,0xac},{0x4124b4L,0x10},{0x40520cL,10},{0x4054a4L,6},{0x40557aL,6}}) {
            byte[] bytes=getBytes(toAddr(range[0]),(int)range[1]);Map<String,Object> window=new LinkedHashMap<>();
            window.put("address",String.format("%08x",range[0]));window.put("hex",HexFormat.of().formatHex(bytes));
            window.put("sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));windows.add(window);
        }
        result.put("windows",windows);
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long pc:visited) {
                var instruction=getInstructionAt(toAddr(pc));
                if(instruction==null)throw new IllegalStateException("No retained instruction at "+Long.toHexString(pc));
                Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));
                row.put("instruction",instruction.toString());row.put("bytes",HexFormat.of().formatHex(instruction.getBytes()));
                w.write(json.toJson(row));w.newLine();
            }
        }
        Files.writeString(out.resolve("verification.json"),json.toJson(result),StandardCharsets.UTF_8);
        println("CUKTECH ADC conversion verified: "+total+" cases; "+instructionSteps+" instructions");
    }
}
