// Verify the original thermal corrector's final switch with synthetic inputs.
// Excludes the earlier load classifier, sensors, I2C, BLE and ROM execution.
// Arg: new absolute output directory. Use a read-only 0073 project copy.
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
 * Checks the final switch of the original thermal corrector. It covers all 256 raw NTC2 bytes,
 * load states 0..8 and 255, and AC selector 0 and 1. The updated load state is an input. The
 * earlier load classifier does not run.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-thermal-correction}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code cases.jsonl}: one row for each synthetic case, with inputs and observed results.</li>
 * <li>{@code verification.json}: image hash, counts, stops and the scope of the check.</li>
 * </ul>
 *
 * Program changes: none. All writes go to the emulator state only.
 * Run it on a read-only project copy.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output directory already exists. It stops with an exception if an observed result differs from the expected result.
 */
public class VerifyThermalCorrection extends GhidraScript {
    private long totalSteps;
    private long modeCallbacks;
    @SuppressWarnings("unchecked")
    private void fixedThumbWorkaround(EmulatorHelper helper) throws Exception {
        // Same instance-local Ghidra 12.1.4 workaround as VerifyAdcConversion.
        // TBB also invokes the faulty setISAMode handler. Reject ARM transitions.
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
                long address=emulate.getExecuteAddress().getOffset();
                if((address&1)!=0)emulate.setExecuteAddress(toAddr(address&~1L));modeCallbacks++;
            });replaced=true;
        }
        if(!replaced)throw new IllegalStateException("Expected ARM handler not found");
    }
    private int correction(int raw,int state,int acSelector) throws Exception {
        EmulatorHelper emu=new EmulatorHelper(currentProgram);
        try {
            fixedThumbWorkaround(emu);
            emu.writeMemory(toAddr(0x2000ceb1L),new byte[]{(byte)state,(byte)acSelector});
            emu.writeRegister("r0",0);emu.writeRegister("r1",0);
            emu.writeRegister("r5",(byte)raw);emu.writeRegister("r6",0x2000cea8L);
            emu.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);
            emu.writeRegister(emu.getPCRegister(),0x409292L);int steps=0;
            while(!emu.getExecutionAddress().equals(toAddr(0x4092b4L))) {
                long pc=emu.getExecutionAddress().getOffset();monitor.checkCancelled();
                if(pc<0x409292L||pc>0x4092b2L||(pc>=0x4092a4L&&pc<=0x4092a7L))throw new IllegalStateException("Escaped correction instructions");
                if(++steps>20)throw new IllegalStateException("Correction budget exceeded");
                if(!emu.step(monitor))throw new IllegalStateException(emu.getLastError());
            }
            totalSteps+=steps;return emu.readRegister("r0").intValue();
        }finally{emu.dispose();}
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        Files.createDirectories(out);Gson json=new Gson();int count=0;
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)) {
            for(int state:new int[]{0,1,2,3,4,5,6,7,8,255})for(int ac:new int[]{0,1})for(int raw=0;raw<256;raw++) {
                int subtract=ac==0?(state==4||state==7?10:state==5?3:state==6?7:0):0;
                int expected=(byte)((byte)raw-subtract),actual=correction(raw,state,ac);
                Map<String,Object> row=new LinkedHashMap<>();row.put("raw_ntc2_byte",raw);row.put("updated_load_state",state);row.put("ac_selector",ac);
                row.put("expected",expected);row.put("observed",actual);w.write(json.toJson(row));w.newLine();
                if(actual!=expected)throw new IllegalStateException("Mismatch: "+json.toJson(row));count++;
            }
        }
        byte[] window=getBytes(toAddr(0x409292L),0x24);Map<String,Object> result=new LinkedHashMap<>();
        result.put("sha256",sha);result.put("entry","00409292");result.put("window_hex",HexFormat.of().formatHex(window));
        result.put("window_sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(window)));
        result.put("cases",count);result.put("instruction_steps",totalSteps);result.put("all_expected_results_match",true);
        result.put("mode_callbacks",modeCallbacks);
        result.put("emulator_workaround","Instance-local replacement of Ghidra 12.1.4 setISAMode callback: assert Thumb, align odd PC, retain existing Thumb context. Original p-code is unchanged; no ARM-mode transition allowed.");
        result.put("scope","Final correction block only, all 256 raw NTC2 bytes, load states 0..8 and 255, AC selector 0/1. Updated load state is supplied, not predicted. No sensor acquisition, ROM or peripheral execution.");
        result.put("stop_boundary","Before original POP PC at 004092b4, after signed-byte result computation");
        Files.writeString(out.resolve("verification.json"),json.toJson(result),StandardCharsets.UTF_8);
        println("CUKTECH thermal correction verified: "+count+" cases; "+totalSteps+" instructions");
    }
}
