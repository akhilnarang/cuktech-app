// Original 0073 allocation manager, elapsed helper and desired-cap callbacks.
// Arg: new output directory. Synthetic RAM; no charger/bus/peripheral execution.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.pcode.emulate.*;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.*;
import com.google.gson.Gson;

/**
 * Checks the original allocation manager, the elapsed-time helper and the desired-cap callbacks.
 * One sequence keeps the emulator RAM for six calls: startup wait, release, shutdown and recovery.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-allocation-manager}</li>
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
public class VerifyAllocationManager extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private static final long BASE=0x2000ce98L,CTX=0x2000cea8L;
    private static final int LENGTH=0x180;
    private long steps,callbacks;private final TreeSet<Long> visited=new TreeSet<>();
    private static class Input {
        String name="stable";int gate=3,stage=0,dirty=0,storedCount=2,storedSum=200,mode=0,storedMode=0,scene=2,storedScene=2,enabled=15,storedDisabled=0,adcState=0,classifier=2,reconcile=0,ac=1,hardware=0;
        long start=100,now=100,refreshStart=0;boolean actualAllocator=false;
        int[] states={2,2,0,0},hints={100,100,0,0},current={7,4,96,96},profile={7,4,96,96};
    }
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
    private void ret(EmulatorHelper e,int value){long pc=e.readRegister("lr").longValue()&~1L;e.writeRegister("r0",Integer.toUnsignedLong(value));e.writeRegister(e.getPCRegister(),pc);}
    private void b(byte[] data,long address,int value){data[(int)(address-BASE)]=(byte)value;}
    private int b(byte[] data,long address){return Byte.toUnsignedInt(data[(int)(address-BASE)]);}
    private void half(byte[] data,long address,int value){for(int n=0;n<2;n++)b(data,address+n,value>>>(n*8));}
    private void word(byte[] data,long address,long value){for(int n=0;n<4;n++)b(data,address+n,(int)(value>>>(n*8)));}
    private long capAddress(int port){return port<2?0x2000cf3aL+port*5:port==2?CTX+4:CTX+3;}
    private long elapsed(long now,long start){return (now-start-(now<start?1:0))&0xffffffffL;}
    private byte[] context(Input in){
        byte[] data=new byte[LENGTH];Arrays.fill(data,0,16,(byte)0x6b);Arrays.fill(data,LENGTH-16,LENGTH,(byte)0x6b);
        b(data,CTX,0x5b);b(data,CTX+1,in.adcState);b(data,CTX+7,in.gate);b(data,CTX+10,in.ac);b(data,CTX+11,in.storedCount);b(data,CTX+14,in.stage);b(data,CTX+15,in.dirty);b(data,CTX+0x17,in.storedMode);b(data,CTX+0x1b,in.storedScene);b(data,CTX+0x1d,in.storedDisabled);
        half(data,CTX+0x24,0x1234);half(data,CTX+0x2c,in.storedSum);word(data,CTX+0x30,in.refreshStart);word(data,CTX+0x3c,in.start);
        for(int p=0;p<4;p++){b(data,CTX+0x7a+p,in.states[p]);half(data,0x2000cf58L+p*4,in.hints[p]);b(data,capAddress(p),in.current[p]);}
        return data;
    }
    private Map<String,Object> invoke(EmulatorHelper e,Input in,byte[] before) throws Exception {
        long begin=steps;byte[] expected=before.clone();int count=0,sum=0,disabled=(~in.enabled)&15;
        for(int p=0;p<4;p++)if(in.states[p]!=0){count++;sum+=in.hints[p];}
        int nextGate=in.gate;if(nextGate==1&&elapsed(in.now,in.start)>=1500)nextGate=2;
        boolean full=count!=0&&in.storedCount==count&&in.storedScene==1&&elapsed(in.now,in.refreshStart)>=60000;
        if(full)word(expected,CTX+0x30,in.now);
        boolean recalc=in.storedCount!=count||in.storedSum!=(sum&65535)||in.storedMode!=in.mode||in.storedDisabled!=disabled||in.dirty!=0||in.storedScene!=in.scene||nextGate==2||in.adcState==3||in.classifier>=3;
        int budget=new int[]{1200,1200,900,0}[in.stage],remaining=(short)(budget-sum);
        b(expected,CTX+7,nextGate);
        int[] output=in.profile.clone();if(budget==0)Arrays.fill(output,0);
        if(in.actualAllocator&&budget!=0)output=budget==900?new int[]{6,1,96,96}:new int[]{7,4,96,96};
        ArrayList<List<Integer>> wantedDispatch=new ArrayList<>(),dispatch=new ArrayList<>();
        if(recalc){
            b(expected,CTX,0);b(expected,CTX+15,0);b(expected,CTX+11,count);half(expected,CTX+0x2c,sum);b(expected,CTX+0x1b,in.scene);b(expected,CTX+0x1d,disabled);
            if(in.actualAllocator&&budget!=0){half(expected,CTX+0x24,remaining);b(expected,CTX+0x19,disabled);}
            if(nextGate<2)output[1]=0;
            for(int p=0;p<4;p++)if(in.current[p]!=output[p]||p==3){
                wantedDispatch.add(Arrays.asList(p,output[p]));b(expected,capAddress(p),output[p]);
                if(p==0&&nextGate==0){nextGate=1;word(expected,CTX+0x3c,in.now);}else if(p==1&&output[p]!=0)nextGate=3;
            }
            b(expected,CTX+7,nextGate);
        }
        e.writeRegister("sp",0x2007c000L);e.writeRegister("lr",0x40306bL);e.writeRegister("r0",in.mode);e.writeRegister(e.getPCRegister(),0x4084c8L);
        int loops=0,allocate=0,zero=0,fullCalls=0,quickCalls=0,reconcileCalls=0;
        while(true){monitor.checkCancelled();if(++loops>5000)throw new IllegalStateException("Runaway manager "+in.name);long pc=e.getExecutionAddress().getOffset();if(pc==0x40306aL)break;
            if(pc==0x406b78L||pc==0x406db4L){if(pc==0x406b78L)fullCalls++;else quickCalls++;ret(e,in.classifier);continue;}
            if(pc==0x409784L||pc==0x406984L||pc==0x4239b8L||pc==0x4051b6L||pc==0x424dc0L){ret(e,0);continue;}
            if(pc==0x404784L){if(r(e,0)!=3)throw new IllegalStateException("Wrong scene selector");ret(e,in.scene);continue;}
            if(pc==0x423414L){ret(e,(int)in.now);continue;}
            if(pc==0x417d60L){ret(e,in.hardware);continue;}
            if(pc==0x406e30L){allocate++;if(r(e,1)!=in.mode||r(e,2)!=remaining||r(e,3)!=budget)throw new IllegalStateException("Wrong allocator arguments");if(!in.actualAllocator){byte[] row=new byte[4];for(int p=0;p<4;p++)row[p]=(byte)in.profile[p];e.writeMemory(toAddr(Integer.toUnsignedLong(r(e,0))),row);ret(e,0);continue;}}
            if(pc==0x409dc8L)zero++;
            if(pc==0x409e64L)dispatch.add(Arrays.asList(r(e,0),r(e,1)));
            if(pc==0x40a498L){int port=r(e,0);if(port<2||port>3)throw new IllegalStateException("Bad SC port");e.writeMemory(toAddr(capAddress(port)),new byte[]{(byte)r(e,1)});ret(e,0);continue;}
            if(pc==0x40a5f4L){int port=r(e,0);if(port<0||port>1)throw new IllegalStateException("Bad C port");reconcileCalls++;ret(e,in.reconcile);continue;}
            boolean allowed=(pc>=0x4084c8L&&pc<0x4086c0L)||(pc>=0x4092c0L&&pc<0x4092d6L)||(pc>=0x4093acL&&pc<0x4093bcL)||(pc>=0x409dc8L&&pc<0x409dd8L)||(pc>=0x409e64L&&pc<0x409e84L)||(pc>=0x40a954L&&pc<0x40a99eL)||(pc>=0x415d2cL&&pc<0x415d44L)||(pc>=0x409078L&&pc<0x40909eL);
            if(in.actualAllocator)allowed|=(pc>=0x406e30L&&pc<0x4084c8L)||(pc>=0x4052d2L&&pc<0x4057c4L)||(pc>=0x4092e0L&&pc<0x4093bcL);
            if(!allowed)throw new IllegalStateException("Escaped manager "+Long.toHexString(pc));visited.add(pc);if(!e.step(monitor))throw new IllegalStateException(e.getLastError());steps++;
        }
        byte[] actual=e.readMemory(toAddr(BASE),LENGTH);
        if(!Arrays.equals(expected,actual)){ArrayList<String> changes=new ArrayList<>();for(int n=0;n<LENGTH;n++)if(expected[n]!=actual[n])changes.add(String.format("%08x expected%02x actual%02x",BASE+n,expected[n]&255,actual[n]&255));throw new IllegalStateException("Context mismatch "+in.name+": "+changes);}
        if(!wantedDispatch.equals(dispatch)||allocate!=(recalc&&budget!=0?1:0)||zero!=(recalc&&budget==0?1:0)||fullCalls!=(full?1:0)||quickCalls!=(full?0:1)||reconcileCalls!=dispatch.stream().filter(a->a.get(0)<2).count())throw new IllegalStateException("Manager callback mismatch "+in.name);
        Map<String,Object> row=new LinkedHashMap<>();row.put("name",in.name);row.put("gate_before",in.gate);row.put("gate_after",nextGate);row.put("clock_start",in.start);row.put("clock_now",in.now);row.put("elapsed_helper_value",elapsed(in.now,in.start));row.put("stage",in.stage);row.put("dirty_before",in.dirty);row.put("recalculated",recalc);row.put("actual_allocator",in.actualAllocator);row.put("allocator_calls",allocate);row.put("zero_row_calls",zero);row.put("budget",budget);row.put("remaining_signed16",remaining);row.put("full_classifier_calls",fullCalls);row.put("quick_classifier_calls",quickCalls);row.put("reconciler_scripted_result",in.reconcile);row.put("dispatch",dispatch);row.put("complete_context_and_guards_match",true);row.put("instruction_steps",steps-begin);return row;
    }
    private Map<String,Object> check(Input in) throws Exception {
        EmulatorHelper e=fixture();try{byte[] data=context(in);e.writeMemory(toAddr(BASE),data);byte[] defaults={11,11,(byte)128,112,96,11,11,(byte)128,112,96};for(int p=0;p<4;p++)if((in.enabled&(1<<p))==0)defaults[5+p]=0;e.writeMemory(toAddr(0x2000c2b6L),defaults);e.writeMemory(toAddr(0x2000ec18L),new byte[32]);e.writeMemory(toAddr(0x2000c998L),new byte[24]);return invoke(e,in,data);}finally{e.dispose();}
    }
    public void run() throws Exception {
        if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);Gson json=new Gson();int count=0;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)){
            for(int trigger=0;trigger<13;trigger++){Input in=new Input();in.name=new String[]{"stable","count","hint_sum","port_mode","disabled_mask","dirty","scene","gate2","ADC_state3","classifier3","thermal_stage_without_dirty_synthetic","AC_selector_without_dirty_synthetic","classifier4"}[trigger];switch(trigger){case 1->in.storedCount=1;case 2->in.storedSum=199;case 3->in.mode=1;case 4->in.enabled=14;case 5->in.dirty=1;case 6->in.storedScene=1;case 7->in.gate=2;case 8->in.adcState=3;case 9->in.classifier=3;case 10->in.stage=2;case 11->in.ac=0;case 12->in.classifier=4;}w.write(json.toJson(check(in)));w.newLine();count++;}
            for(int gate=0;gate<4;gate++)for(int delta:new int[]{0,1499,1500,1501})for(long start:new long[]{100,0xffffff00L})for(int result=0;result<2;result++)for(int same=0;same<4;same++){Input in=new Input();in.name="gate_matrix";in.gate=gate;in.start=start;in.now=(start+delta)&0xffffffffL;in.reconcile=result;in.dirty=1;in.current=new int[]{(same&1)!=0?7:0,(same&2)!=0?4:0,96,96};w.write(json.toJson(check(in)));w.newLine();count++;}
            for(int stage:new int[]{0,1,2,3,2,1,0}){Input in=new Input();in.name="real_allocator_stage_projection";in.stage=stage;in.dirty=1;in.actualAllocator=true;w.write(json.toJson(check(in)));w.newLine();count++;}
            for(int delta:new int[]{59999,60000,60001}){Input in=new Input();in.name="AI_refresh_boundary";in.scene=in.storedScene=1;in.now=100L+delta;in.refreshStart=100;w.write(json.toJson(check(in)));w.newLine();count++;}
            for(int state:new int[]{0,1,2}){Input in=new Input();in.name="host_state_sum_gate";in.states=new int[]{state,0,0,0};in.hints=new int[]{270,600,0,0};in.dirty=1;w.write(json.toJson(check(in)));w.newLine();count++;}
            // Reuse emulator RAM across six calls: startup wait, release, shutdown and recovery.
            EmulatorHelper e=fixture();try{Input in=new Input();in.name="sequence_start";in.gate=0;in.current=new int[]{0,0,0,0};in.dirty=1;byte[] data=context(in);e.writeMemory(toAddr(BASE),data);e.writeMemory(toAddr(0x2000c2b6L),new byte[]{11,11,(byte)128,112,96,11,11,(byte)128,112,96});
                for(int n=0;n<6;n++){if(n!=0){data=e.readMemory(toAddr(BASE),LENGTH);in.gate=b(data,CTX+7);in.current=new int[]{b(data,capAddress(0)),b(data,capAddress(1)),b(data,capAddress(2)),b(data,capAddress(3))};in.start=100;in.now=new long[]{100,1599,1600,1601,1602,1603}[n];in.dirty=n>=3?1:0;in.stage=n==3?3:n==4?2:0;b(data,CTX+15,in.dirty);b(data,CTX+14,in.stage);in.storedCount=2;in.storedSum=200;in.name="sequence_"+n;e.writeMemory(toAddr(BASE),data);}w.write(json.toJson(invoke(e,in,data)));w.newLine();count++;}
            }finally{e.dispose();}
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)){for(long pc:visited){var ins=getInstructionAt(toAddr(pc));if(ins==null){clearListing(toAddr(pc),toAddr(pc));new ArmDisassembleCommand(toAddr(pc),null,true).applyTo(currentProgram,monitor);ins=getInstructionAt(toAddr(pc));}if(ins==null)throw new IllegalStateException("No instruction");Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("cases",count);meta.put("instruction_steps",steps);meta.put("distinct_executed_instructions",visited.size());meta.put("mode_callbacks",callbacks);meta.put("all_expected_results_match",true);
        meta.put("scope","Original manager, actual elapsed helper, thermal budget getter, zero row, cap getter, dispatcher and USB-C desired callbacks. Seven stage projections also execute original allocator and Apple scene variants. Other allocation calls use a scripted four-cap row; classifier/current scene/probe/UI/log/timer source/reconciler bodies scripted. SC callback uses explicit desired-cache update stub; no SC register/bus code. Complete synthetic context and guards compared, argument/callback order, all recalculation triggers and suppressed triggers, elapsed1499/1500/1501 including wrap, result0/1, AI refresh59999/60000/60001 and six retained-RAM manager calls. Stage projections and sequence inject thermalstage/dirty rather than executing thermal evaluator/scheduler. No physical ACK, calibration, negotiation, sustained hardware timeline or liveness guarantee. Fixed-Thumb instance workaround changes no original bytes/p-code.");Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);println("Allocation manager: "+count+" cases / "+steps+" original steps");
    }
}
