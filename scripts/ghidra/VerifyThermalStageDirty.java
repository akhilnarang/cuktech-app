// AD1204 0073 original thermal evaluator: stage hysteresis and allocation dirty flag.
// Arg: NEW absolute output directory. Synthetic RAM; no peripherals or charger writes.
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
 * Checks the original thermal evaluator: the stage hysteresis and the allocation dirty flag.
 * The corrected sensor value, the hardware getter, the logs and the tail publisher are scripted.
 * The graphic value is observed. It is not predicted independently.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-thermal-stage-dirty}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code cases.jsonl}: one row for each synthetic case, with inputs and observed results.</li>
 * <li>{@code executed-instructions.jsonl}: each distinct original instruction that ran, with its bytes.</li>
 * <li>{@code verification.json}: image hash, counts, stops and the scope of the check.</li>
 * </ul>
 *
 * Program changes: if an executed address has no instruction in the listing, it disassembles
 * that address while it writes {@code executed-instructions.jsonl}. It does not change firmware
 * bytes. Run it with {@code -readOnly} so that Ghidra discards these changes.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output directory already exists. It stops with an exception if an observed result differs from the expected result.
 */
public class VerifyThermalStageDirty extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private static final long BASE=0x2000ce98L, CTX=0x2000cea8L, STOP=0x40306aL;
    private long steps,modeCallbacks; private final TreeSet<Long> visited=new TreeSet<>();
    private int fixtureCount,publisherCalls;
    @SuppressWarnings("unchecked")
    private EmulatorHelper fixture() throws Exception {
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        var outer=e.getEmulator().getClass().getDeclaredField("emulator");outer.setAccessible(true);Emulate engine=(Emulate)outer.get(e.getEmulator());
        var field=Emulate.class.getDeclaredField("instructionStateModifier");field.setAccessible(true);var modifier=(EmulateInstructionStateModifier)field.get(engine);
        var mapping=EmulateInstructionStateModifier.class.getDeclaredField("pcodeOpMap");mapping.setAccessible(true);Map<Integer,OpBehaviorOther> operations=(Map<Integer,OpBehaviorOther>)mapping.get(modifier);boolean found=false;
        for(int n:new ArrayList<>(operations.keySet()))if("setISAMode".equals(currentProgram.getLanguage().getUserDefinedOpName(n))){operations.put(n,(emulate,output,inputs)->{if(emulate.getMemoryState().getValue(currentProgram.getRegister("ISAModeSwitch"))!=1)throw new IllegalStateException("ARM transition");long pc=emulate.getExecuteAddress().getOffset();if((pc&1)!=0)emulate.setExecuteAddress(toAddr(pc&~1L));modeCallbacks++;});found=true;}
        if(!found)throw new IllegalStateException("Missing mode callback");return e;
    }
    private int r(EmulatorHelper e,int n){return e.readRegister("r"+n).intValue();}
    private void ret(EmulatorHelper e,int value){long next=e.readRegister("lr").longValue()&~1L;e.writeRegister("r0",Integer.toUnsignedLong(value));e.writeRegister(e.getPCRegister(),next);}
    private int off(int n){return Math.toIntExact(CTX-BASE)+n;}
    private int b(byte[] a,int n){return Byte.toUnsignedInt(a[off(n)]);}
    private void b(byte[] a,int n,int v){a[off(n)]=(byte)v;}
    private int h(byte[] a,int n){return b(a,n)|(b(a,n+1)<<8);}
    private void h(byte[] a,int n,int v){b(a,n,v);b(a,n+1,v>>>8);}
    private int[] thresholds(int ac,int hw,int stage){
        int[][] table=ac==0?(hw!=0?new int[][]{{73,-128},{87,70},{110,75},{127,75}}:new int[][]{{80,-128},{92,75},{112,85},{127,75}}):(hw!=0?new int[][]{{80,-128},{96,75},{112,85},{127,75}}:new int[][]{{80,-128},{97,75},{112,85},{127,75}});
        return table[stage];
    }
    private byte[] initial(int ac,int stage,int temp,int countdown,int counter,int dirty){byte[] a=new byte[0xb0];Arrays.fill(a,(byte)0x6b);b(a,0xa,ac);b(a,0xc,temp);b(a,0xd,countdown);b(a,0xe,stage);b(a,0xf,dirty);b(a,0x10,64);h(a,0x20,counter);return a;}
    private byte[] expected(byte[] input,int sensor,int hw){
        byte[] a=input.clone();int old=(byte)b(a,0xc),countdown=b(a,0xd);boolean changed=false;
        if(b(a,0xc)==(sensor&255))b(a,0xd,30);
        else if(old+1<sensor||sensor+1<old){b(a,0xc,sensor);b(a,0xd,30);changed=true;}
        else{b(a,0xd,countdown-1);if(countdown<2){b(a,0xc,sensor);b(a,0xd,30);changed=true;}}
        int stage=b(a,0xe),temp=(byte)b(a,0xc),counter=h(a,0x20);int[] t=thresholds(b(a,0xa),hw,stage);
        int direction=temp>t[0]?(stage<3?1:0):(stage!=0&&temp<t[1]?-1:0);
        if(direction==0){if(counter!=0)h(a,0x20,counter-1);}
        else{counter=(counter+1)&65535;h(a,0x20,counter);if(counter>=201){b(a,0xe,stage+direction);h(a,0x20,0);b(a,0xf,1);changed=true;}}
        // Graphic interpolation is exercised but has no independent numeric oracle here.
        // The caller checks it can change only when the original publisher is reached.
        return a;
    }
    private Map<String,Object> check(EmulatorHelper e,String label,byte[] input,int sensor,int hw) throws Exception {
        byte[] wanted=expected(input,sensor,hw);int beforeStage=b(input,0xe),afterStage=b(wanted,0xe);boolean changedTemp=b(input,0xc)!=b(wanted,0xc),publishExpected=changedTemp||beforeStage!=afterStage;
        long begin=steps;int iterations=0,reads=0,publishes=0,publishedStage=-1,publishedGraphic=-999;
        e.writeMemory(toAddr(BASE),input);for(int n=0;n<13;n++)e.writeRegister("r"+n,0);for(String f:new String[]{"CY","OV","NG","ZR"})e.writeRegister(f,0);
        e.writeRegister("sp",0x2007c000L);e.writeRegister("lr",STOP|1L);e.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);e.writeRegister(e.getPCRegister(),0x408c7cL);
        while(true){monitor.checkCancelled();if(++iterations>500)throw new IllegalStateException("Runaway evaluator "+label);long pc=e.getExecutionAddress().getOffset();if(pc==STOP)break;
            if(pc==0x4090a4L){reads++;ret(e,sensor);continue;}
            if(pc==0x417d60L){ret(e,hw);continue;}
            if(pc==0x4239b8L||pc==0x4051b6L){ret(e,0);continue;}
            if(pc==0x406aa4L){publishes++;publisherCalls++;publishedStage=r(e,0);publishedGraphic=r(e,1);ret(e,0);continue;}
            if(pc<0x408c7cL||pc>=0x408e44L)throw new IllegalStateException("Escaped evaluator "+Long.toHexString(pc));
            visited.add(pc);if(!e.step(monitor))throw new IllegalStateException(e.getLastError());steps++;
        }
        byte[] actual=e.readMemory(toAddr(BASE),input.length);if(publishes==1)b(wanted,0x10,b(actual,0x10));
        if(reads!=1||publishes!=(publishExpected?1:0)||!Arrays.equals(wanted,actual)||(publishes==1&&(publishedStage!=afterStage||publishedGraphic!=(byte)b(actual,0x10))))throw new IllegalStateException("Thermal mismatch "+label+" stage "+beforeStage+" -> "+b(actual,0xe)+" expected "+afterStage+" counter "+h(actual,0x20)+" expected "+h(wanted,0x20)+" publishes="+publishes+" expected="+publishExpected);
        fixtureCount++;Map<String,Object> row=new LinkedHashMap<>();row.put("label",label);row.put("ac_selector",b(input,0xa));row.put("hardware_flag",hw);row.put("sensor_signed_byte",sensor);row.put("initial_shell_signed_byte",(byte)b(input,0xc));row.put("initial_countdown",b(input,0xd));row.put("initial_stage",beforeStage);row.put("initial_counter",h(input,0x20));row.put("initial_dirty",b(input,0xf));row.put("expected_stage",afterStage);row.put("expected_counter",h(wanted,0x20));row.put("expected_dirty",b(wanted,0xf));row.put("expected_shell_signed_byte",(byte)b(wanted,0xc));row.put("expected_countdown",b(wanted,0xd));row.put("publisher_calls",publishes);row.put("observed_graphic_signed_byte",(byte)b(actual,0x10));row.put("entire_context_and_guards_match",true);row.put("instruction_steps",steps-begin);row.put("result_context_hex",HexFormat.of().formatHex(actual));return row;
    }
    private void writeCase(java.io.BufferedWriter w,Gson json,String label,byte[] context,int sensor,int hw) throws Exception {EmulatorHelper e=fixture();try{w.write(json.toJson(check(e,label,context,sensor,hw)));w.newLine();}finally{e.dispose();}}
    public void run() throws Exception {
        if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);Gson json=new Gson();List<Map<String,Object>> events=new ArrayList<>();
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)){
            for(int ac:new int[]{0,1})for(int hw:new int[]{0,1})for(int stage=0;stage<4;stage++){
                Set<Integer> samples=new TreeSet<>();for(int threshold:thresholds(ac,hw,stage))for(int delta:new int[]{-1,0,1})if(threshold+delta>=-128&&threshold+delta<=127)samples.add(threshold+delta);
                for(int temp:samples)for(int counter:new int[]{0,199,200})for(int dirty:new int[]{0,1})writeCase(w,json,"threshold",initial(ac,stage,temp,30,counter,dirty),temp,hw);
            }
            for(int old:new int[]{-128,-1,0,25,126,127})for(int delta:new int[]{-2,-1,0,1,2})for(int countdown:new int[]{0,1,2,30,255})if(old+delta>=-128&&old+delta<=127)writeCase(w,json,"shell_countdown",initial(1,0,old,countdown,0,0),old+delta,0);
            // One retained-state heating/cooling cycle: initial count200 -> first
            // transition at call1; each later transition needs201 qualifying calls.
            EmulatorHelper e=fixture();byte[] state=initial(1,0,25,30,200,0);int ordinal=0;
            try{for(int sensor:new int[]{127,0}){int target=sensor==127?3:0;int calls=0;while(b(state,0xe)!=target){int oldStage=b(state,0xe);Map<String,Object> row=check(e,"sequential_cycle",state,sensor,0);w.write(json.toJson(row));w.newLine();state=HexFormat.of().parseHex((String)row.get("result_context_hex"));ordinal++;calls++;if(b(state,0xe)!=oldStage){Map<String,Object> event=new LinkedHashMap<>();event.put("call",ordinal);event.put("sensor_signed_byte",sensor);event.put("from",oldStage);event.put("to",b(state,0xe));event.put("dirty",b(state,0xf));events.add(event);}if(calls>700)throw new IllegalStateException("Cycle stalled");/* Manager consumption between scheduler cycles is scripted. */b(state,0xf,0);}}}finally{e.dispose();}
        }
        int[] eventCalls={1,202,403,604,805,1006},eventStages={1,2,3,2,1,0};
        if(events.size()!=6)throw new IllegalStateException("Wrong cycle event count");
        for(int n=0;n<6;n++)if(!events.get(n).get("call").equals(eventCalls[n])||!events.get(n).get("to").equals(eventStages[n])||!events.get(n).get("dirty").equals(1))throw new IllegalStateException("Wrong cycle event "+json.toJson(events.get(n)));
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)){for(long pc:visited){var ins=getInstructionAt(toAddr(pc));if(ins==null){disassemble(toAddr(pc));ins=getInstructionAt(toAddr(pc));}if(ins==null)throw new IllegalStateException("No instruction at "+Long.toHexString(pc));Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("entry","00408c7c");meta.put("cases",fixtureCount);meta.put("instruction_steps",steps);meta.put("distinct_executed_instructions",visited.size());meta.put("mode_callbacks",modeCallbacks);meta.put("publisher_calls",publisherCalls);meta.put("all_expected_results_match",true);meta.put("sequential_stage_events",events);
        meta.put("scope","Original evaluator instructions including signed threshold lookup, countdown, transition counter, dirty writes and graphic interpolation. Corrected sensor4090a4, hardware getter417d60, logs and tail publisher406aa4 are scripted. Entire manager context and guards compared; numeric graphic is observed, not independently predicted. Publisher stage/graphic arguments are checked against resulting context. Sequential cycle retains complete prior context, resetting dirty to0 to model manager consumption between calls; manager and scheduler are not executed. No wall-clock scale, acquisition calibration, IRQ concurrency, bus writes or controller acceptance tested. Instance-local fixed-Thumb workaround changes no original instructions or p-code.");
        Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH thermal stage dirty: "+fixtureCount+" cases / "+steps+" original steps");
    }
}
