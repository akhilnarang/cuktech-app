// Original 0073 allocation dispatcher and USB-C callback; no bus/peripheral execution.
// Arg: a new output directory. External reconciliation result is scripted.
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
 * Checks the original allocation dispatcher (0x00409e64) and the USB-C callback (0x0040a954).
 * The external reconciliation result comes from a scripted stub.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-c2-startup-gate}</li>
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
public class VerifyC2StartupGate extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private static final long BASE=0x2000ce98L, GATE=0x2000ceafL, TICKS=0x2000cee4L, NOW=0x55667788L;
    private long steps, callbacks;
    private final TreeSet<Long> visited=new TreeSet<>();
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
    private void word(byte[] buffer,long address,long value){for(int i=0;i<4;i++)buffer[(int)(address-BASE)+i]=(byte)(value>>>(i*8));}
    private Map<String,Object> invoke(EmulatorHelper e,byte[] expected,int port,int cap,int ignoredIncomingR2,int helperResult) throws Exception {
        int gate=Byte.toUnsignedInt(expected[(int)(GATE-BASE)]),nextGate=gate,timers=0,helpers=0,logs=0,iterations=0;long begin=steps;
        boolean starts=port==0&&gate==0;
        if(starts){nextGate=1;word(expected,TICKS,NOW);}else if(port==1&&cap!=0)nextGate=3;
        expected[(int)(GATE-BASE)]=(byte)nextGate;expected[(int)(0x2000cf3aL+port*5-BASE)]=(byte)cap;
        e.writeRegister("sp",0x2007c000L);e.writeRegister("lr",0x40306bL);e.writeRegister("r0",port);e.writeRegister("r1",cap);e.writeRegister("r2",ignoredIncomingR2);e.writeRegister(e.getPCRegister(),0x409e64L);
        while(true){monitor.checkCancelled();if(++iterations>160)throw new IllegalStateException("Runaway startup callback");long pc=e.getExecutionAddress().getOffset();if(pc==0x40306aL)break;
            if(pc==0x4239b8L){if(r(e,1)!=port||r(e,2)!=(cap==0?0:1)||r(e,3)!=cap)throw new IllegalStateException("Wrong log/normalized-enable arguments");logs++;ret(e,0);continue;}
            if(pc==0x4051b6L){ret(e,0);continue;}
            if(pc==0x415d2cL){if(!starts||!Arrays.equals(new byte[]{1},e.readMemory(toAddr(GATE),1)))throw new IllegalStateException("Timer called without gate set first");timers++;ret(e,(int)NOW);continue;}
            if(pc==0x40a5f4L){if(r(e,0)!=port||!Arrays.equals(expected,e.readMemory(toAddr(BASE),expected.length)))throw new IllegalStateException("Desired cap/gate/timestamp not stored before reconciliation");helpers++;ret(e,helperResult);continue;}
            if(!((pc>=0x409e64L&&pc<0x409e84L)||(pc>=0x40a954L&&pc<0x40a99eL)))throw new IllegalStateException("Escaped dispatcher/callback "+Long.toHexString(pc));
            visited.add(pc);if(!e.step(monitor))throw new IllegalStateException(e.getLastError());steps++;
        }
        if(timers!=(starts?1:0)||helpers!=1||logs!=1||!Arrays.equals(expected,e.readMemory(toAddr(BASE),expected.length)))throw new IllegalStateException("Startup callback mismatch");
        Map<String,Object> row=new LinkedHashMap<>();row.put("port",port);row.put("cap",cap);row.put("gate_before",gate);row.put("gate_after",nextGate);row.put("incoming_r2_overwritten_by_dispatcher",ignoredIncomingR2);row.put("reconciler_result",helperResult);row.put("timer_calls",timers);row.put("reconciler_calls",helpers);row.put("complete_context_and_guards_match",true);row.put("stored_before_reconciler",true);row.put("instruction_steps",steps-begin);return row;
    }
    private Map<String,Object> check(int port,int gate,int cap,int ignored,int result) throws Exception {
        EmulatorHelper e=fixture();byte[] expected=new byte[0x160];Arrays.fill(expected,(byte)0x6b);expected[(int)(GATE-BASE)]=(byte)gate;word(expected,TICKS,0x11223344L);
        try{e.writeMemory(toAddr(BASE),expected);return invoke(e,expected,port,cap,ignored,result);}finally{e.dispose();}
    }
    public void run() throws Exception {
        if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);Gson json=new Gson();int count=0;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)){
            for(int port=0;port<2;port++)for(int gate=0;gate<4;gate++)for(int cap:new int[]{0,7})for(int ignored:new int[]{0,0x55})for(int result=0;result<2;result++){w.write(json.toJson(check(port,gate,cap,ignored,result)));w.newLine();count++;}
            EmulatorHelper e=fixture();byte[] expected=new byte[0x160];Arrays.fill(expected,(byte)0x6b);expected[(int)(GATE-BASE)]=0;word(expected,TICKS,0x11223344L);e.writeMemory(toAddr(BASE),expected);
            try{for(int[] action:new int[][]{{0,0},{1,0},{1,7},{0,0},{1,0}}){Map<String,Object> row=invoke(e,expected,action[0],action[1],0x55,0);row.put("sequence","C1 disabled starts timer; C2 disabled preserves wait; C2 enabled completes; later disable does not rearm");w.write(json.toJson(row));w.newLine();count++;}}finally{e.dispose();}
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)){for(long pc:visited){var ins=getInstructionAt(toAddr(pc));if(ins==null)throw new IllegalStateException("No instruction at "+Long.toHexString(pc));Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("cases",count);meta.put("instruction_steps",steps);meta.put("distinct_executed_instructions",visited.size());meta.put("mode_callbacks",callbacks);meta.put("all_expected_results_match",true);meta.put("entries",new String[]{"00409e64 dispatcher","0040a954 USB-C callback"});meta.put("stop","0040306a return sentinel");meta.put("scope","Original dispatcher and USB-C callback, both ports, gates0/1/2/3, caps0/7, incomingr2 overwritten, reconciler result0/1, plus five sequential calls. All context and guard bytes checked; desired cap and state/timestamp changes asserted before reconciliation. Timer/log/reconciler external helpers stubbed after original branch/call. No manager elapsed-time branch, initialization routine, live scheduler, bus acknowledgement, readback, electrical behavior or hardware execution. The callback stores gate1/timestamp on the first C1 cap dispatch even cap0; any nonzero C2 cap dispatch sets gate3 before reconciliation, irrespective of its result. Instance-local fixed-Thumb workaround changes no original firmware or p-code.");Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH C2 startup callback: "+count+" cases / "+steps+" original steps");
    }
}
