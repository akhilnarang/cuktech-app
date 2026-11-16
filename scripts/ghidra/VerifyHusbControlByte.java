// Original 0073 HUSB configuration reconciler, with scripted external helpers.
// Arg: new output directory. No peripheral, bus or ROM execution.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.*;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.*;
import com.google.gson.Gson;

/**
 * Checks the original HUSB configuration reconciler on both ports. Read, write, checksum, logger
 * and reset helpers are scripted stubs after the original BL.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-husb-control-byte}</li>
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
public class VerifyHusbControlByte extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private long steps,callbacks;private final TreeSet<Long> visited=new TreeSet<>();
    @SuppressWarnings("unchecked")
    private EmulatorHelper fixture() throws Exception {
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        var outer=e.getEmulator().getClass().getDeclaredField("emulator");outer.setAccessible(true);Emulate engine=(Emulate)outer.get(e.getEmulator());
        var field=Emulate.class.getDeclaredField("instructionStateModifier");field.setAccessible(true);var modifier=(EmulateInstructionStateModifier)field.get(engine);
        var mapping=EmulateInstructionStateModifier.class.getDeclaredField("pcodeOpMap");mapping.setAccessible(true);Map<Integer,OpBehaviorOther> operations=(Map<Integer,OpBehaviorOther>)mapping.get(modifier);boolean found=false;
        for(int n:new ArrayList<>(operations.keySet()))if("setISAMode".equals(currentProgram.getLanguage().getUserDefinedOpName(n))){operations.put(n,(emulate,output,inputs)->{if(emulate.getMemoryState().getValue(currentProgram.getRegister("ISAModeSwitch"))!=1)throw new IllegalStateException("ARM transition");long pc=emulate.getExecuteAddress().getOffset();if((pc&1)!=0)emulate.setExecuteAddress(toAddr(pc&~1L));callbacks++;});found=true;}
        if(!found)throw new IllegalStateException("Missing mode callback");
        for(int n=0;n<13;n++)e.writeRegister("r"+n,0);for(String f:new String[]{"CY","OV","NG","ZR"})e.writeRegister(f,0);
        e.writeRegister("sp",0x2007c000L);e.writeRegister("lr",0x40306bL);e.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);return e;
    }
    private int r(EmulatorHelper e,int n){return e.readRegister("r"+n).intValue();}
    private void ret(EmulatorHelper e,int value){long next=e.readRegister("lr").longValue()&~1L;e.writeRegister("r0",Integer.toUnsignedLong(value));e.writeRegister(e.getPCRegister(),next);}
    private Map<String,Object> check(int port,int ufcs,int profile,int state) throws Exception {
        EmulatorHelper e=fixture();long begin=steps;int reads=0,writes=0,resets=0,iterations=0;
        long base=0x2000ce98L,desiredAddress=0x2000cf3aL+port*5;
        byte[] desired={7,0x5a,1,(byte)ufcs},reply=desired.clone(),context=new byte[0x160];Arrays.fill(context,(byte)0x6b);
        System.arraycopy(desired,0,context,(int)(desiredAddress-base),4);context[(int)(0x2000cf22L+port-base)]=(byte)state;
        if(profile>=2){int index=profile==2?2:profile==3?3:profile==4?1:0;reply[index]^=1;}
        try {
            e.writeMemory(toAddr(base),context);e.writeRegister("r0",port);e.writeRegister(e.getPCRegister(),0x40a5f4L);
            while(true){monitor.checkCancelled();if(++iterations>250)throw new IllegalStateException("Runaway reconciler");long pc=e.getExecutionAddress().getOffset();if(pc==0x40a694L||pc==0x40a6a2L)break;
                if(pc==0x414d04L){if(r(e,0)!=port)throw new IllegalStateException("Wrong read port");byte[] data=Arrays.copyOf(reply,5);e.writeMemory(toAddr(Integer.toUnsignedLong(r(e,1))),data);reads++;ret(e,profile==0?0:1);continue;}
                if(pc==0x414f90L){if(r(e,0)!=port||!Arrays.equals(e.readMemory(toAddr(Integer.toUnsignedLong(r(e,1))),4),desired))throw new IllegalStateException("Wrong configuration write");writes++;ret(e,0);continue;}
                if(pc==0x4054eeL){if(r(e,0)!=port)throw new IllegalStateException("Wrong settle-reset port");resets++;ret(e,0);continue;}
                if(pc==0x4054feL||pc==0x4051b6L||pc==0x4239b8L){ret(e,0);continue;}
                if(pc<0x40a5f4L||pc>=0x40a6a4L)throw new IllegalStateException("Escaped reconciler "+Long.toHexString(pc));
                visited.add(pc);if(!e.step(monitor))throw new IllegalStateException(e.getLastError());steps++;
            }
            int expected=profile>=3?1:0;
            if(reads!=1||writes!=expected||resets!=(state!=0?expected:0)||!Arrays.equals(context,e.readMemory(toAddr(base),context.length)))throw new IllegalStateException("Reconciler mismatch: port="+port+",ufcs="+ufcs+",profile="+profile+",state="+state+",reads="+reads+",writes="+writes+",resets="+resets);
            Map<String,Object> row=new LinkedHashMap<>();row.put("port",port);row.put("desired_ufcs_byte",ufcs);row.put("profile",new String[]{"read_failed","equal","byte2_only_diff","byte3_only_diff","byte1_only_diff","byte0_only_diff"}[profile]);row.put("state",state);row.put("read_calls",reads);row.put("write_calls",writes);row.put("settle_reset_calls",resets);row.put("written_payload_hex",writes==0?null:HexFormat.of().formatHex(desired));row.put("desired_context_and_guards_preserved",true);row.put("instruction_steps",steps-begin);return row;
        }finally{e.dispose();}
    }
    public void run() throws Exception {
        if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);Gson json=new Gson();int count=0;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)){
            for(int port=0;port<2;port++)for(int ufcs:new int[]{0,0x3c,255})for(int profile=0;profile<6;profile++)for(int state=0;state<3;state++){w.write(json.toJson(check(port,ufcs,profile,state)));w.newLine();count++;}
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)){for(long pc:visited){var ins=getInstructionAt(toAddr(pc));if(ins==null)throw new IllegalStateException("No instruction");Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("cases",count);meta.put("instruction_steps",steps);meta.put("distinct_executed_instructions",visited.size());meta.put("mode_callbacks",callbacks);meta.put("all_expected_results_match",true);meta.put("entry","0040a5f4");meta.put("stops",new String[]{"0040a694 before POP","0040a6a2 before POP"});
        meta.put("initial_attempt","The first fixture run seeded state at the wrong synthetic address and stopped after nine passing cases. The completed run uses state at2000cf22+port, confirmed by raw literal40a9e4=2000cea8 plus0x7a. The initial partial output is not successful evidence.");
        meta.put("scope","Original reconciler branch/argument behaviour: both ports; synthetic desired byte3 values0/60/255; failed read,equality,isolated mismatch of each byte; states0/1/2. Scripted read81 writes four data bytes plus dummy checksum and returns requested status. Bus/checksum,logger,write-helper and reset-helper bodies are stubbed after original BL. Four-byte written payload checked exactly; complete desired-context buffer/guards preserved. Non-default desired values are synthetic inputs, not recovered host settings or approved tuning. Byte2-only mismatch does not write; byte3 mismatch writes full desired profile, with reset callback for state!=0. Physical ACK/readback, actual reset state change, electrical meaning, runtime writers and negotiation excluded. Instance-local fixed-Thumb callback workaround changes no original firmware/p-code.");
        Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH HUSB control byte: "+count+" cases / "+steps+" original steps");
    }
}
