// Original HUSB settling block and original state/power helpers, synthetic SRAM.
// Arg: NEW output directory. No physical bus, ROM or controller executes.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.callother.OpBehaviorOther;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.*;
import com.google.gson.Gson;

/**
 * Checks the original HUSB settling block and the original state and power helpers. The current
 * protocol updater runs separately, because the real worker commits it after the settling block.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-husb-settling}</li>
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
public class VerifyHusbSettling extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private static final long STACK=0x2007c000L, BASE=0x2000cf28L, MEMORY=0x2000ce98L;
    private static final long CACHE=0x2000c998L, FLAGS=0x2000c8bcL, RETURN=0x40306aL;
    private final TreeSet<Long> visited=new TreeSet<>();
    private final Map<String,Long> stubs=new TreeMap<>();
    private long steps,modeCallbacks;
    private static void require(boolean b,String m){if(!b)throw new IllegalStateException(m);}
    private static void put16(byte[] b,int o,int v){b[o]=(byte)v;b[o+1]=(byte)(v>>8);}
    private static void put32(byte[] b,int o,int v){put16(b,o,v);put16(b,o+2,v>>16);}
    private int reg(EmulatorHelper e,int n){return e.readRegister("r"+n).intValue();}
    private int u8(EmulatorHelper e,long a)throws Exception{return Byte.toUnsignedInt(e.readMemory(toAddr(a),1)[0]);}
    private int u16(EmulatorHelper e,long a)throws Exception{return u8(e,a)|(u8(e,a+1)<<8);}
    private void write16(EmulatorHelper e,long a,int v)throws Exception{byte[] b=new byte[2];put16(b,0,v);e.writeMemory(toAddr(a),b);}
    private void write32(EmulatorHelper e,long a,int v)throws Exception{byte[] b=new byte[4];put32(b,0,v);e.writeMemory(toAddr(a),b);}
    @SuppressWarnings("unchecked")
    private EmulatorHelper fixture()throws Exception{
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        var outer=e.getEmulator().getClass().getDeclaredField("emulator");outer.setAccessible(true);
        Emulate engine=(Emulate)outer.get(e.getEmulator());
        var field=Emulate.class.getDeclaredField("instructionStateModifier");field.setAccessible(true);
        var modifier=(EmulateInstructionStateModifier)field.get(engine);
        var mapping=EmulateInstructionStateModifier.class.getDeclaredField("pcodeOpMap");mapping.setAccessible(true);
        Map<Integer,OpBehaviorOther> ops=(Map<Integer,OpBehaviorOther>)mapping.get(modifier);boolean found=false;
        for(int index:new ArrayList<>(ops.keySet()))if("setISAMode".equals(currentProgram.getLanguage().getUserDefinedOpName(index))){
            ops.put(index,(emulate,out,in)->{
                if(emulate.getMemoryState().getValue(currentProgram.getRegister("ISAModeSwitch"))!=1)throw new IllegalStateException("Unexpected ARM transition");
                long pc=emulate.getExecuteAddress().getOffset();if((pc&1)!=0)emulate.setExecuteAddress(toAddr(pc&~1L));modeCallbacks++;
            });found=true;
        }
        require(found,"Expected setISAMode callback");
        for(int n=0;n<13;n++)e.writeRegister("r"+n,0);
        for(String f:new String[]{"CY","OV","NG","ZR"})e.writeRegister(f,0);
        e.writeRegister("sp",STACK);e.writeRegister("lr",RETURN|1);
        e.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);
        byte[] context=new byte[0x180];Arrays.fill(context,0,16,(byte)0x5a);Arrays.fill(context,context.length-16,context.length,(byte)0x5a);
        e.writeMemory(toAddr(MEMORY),context);e.writeMemory(toAddr(CACHE-8),new byte[32]);e.writeMemory(toAddr(FLAGS-8),new byte[24]);
        return e;
    }
    private void stub(EmulatorHelper e,String name,int result){
        stubs.merge(name,1L,Long::sum);e.writeRegister("r0",Integer.toUnsignedLong(result));
        e.writeRegister(e.getPCRegister(),e.readRegister("lr").longValue()&~1L);
    }
    private boolean original(long pc){
        return (pc>=0x40a81cL&&pc<0x40a82eL)||(pc>=0x40a89aL&&pc<0x40a904L)||
            (pc>=0x409becL&&pc<0x409c18L)||(pc>=0x409c1cL&&pc<0x409ccaL)||
            (pc>=0x409d08L&&pc<0x409d6eL)||(pc>=0x4053acL&&pc<0x4053c0L)||
            (pc>=0x4054eeL&&pc<0x4054f4L)||(pc>=0x405e5cL&&pc<0x405ea8L);
    }
    private void execute(EmulatorHelper e,long stop,int port)throws Exception{
        int limit=0;
        while(e.getExecutionAddress().getOffset()!=stop){
            monitor.checkCancelled();require(++limit<1500,"Runaway fixture");long pc=e.getExecutionAddress().getOffset();
            if(pc==0x4239b8L||pc==0x4051b6L){stub(e,"logger",0);continue;}
            if(pc==0x424dc0L){require(reg(e,0)==10,"Unexpected delay");stub(e,"delay_10_argument_no_wait",0);continue;}
            if(pc==0x409e34L){require(reg(e,0)==port,"Wrong insertion-timestamp port");write32(e,BASE+0x44+4*port,1);stub(e,"insertion_timestamp_fixed_1",0);continue;}
            if(pc==0x403234L){
                int n=reg(e,2);require(n==6,"Unexpected memcmp length");
                byte[] a=e.readMemory(toAddr(Integer.toUnsignedLong(reg(e,0))),n),b=e.readMemory(toAddr(Integer.toUnsignedLong(reg(e,1))),n);
                stub(e,"memcmp_six_semantic",Arrays.equals(a,b)?0:1);continue;
            }
            require(original(pc),"Escaped mapped original code: "+Long.toHexString(pc));visited.add(pc);
            if(!e.step(monitor))throw new IllegalStateException(e.getLastError());steps++;
        }
    }
    private byte[] packet(int port,int protocol,int power,int vendor,int cable){
        byte[] b={(byte)protocol,(byte)power,(byte)vendor,(byte)(vendor>>8),(byte)cable,0};
        int sum=2*(port==0?0x92:0x94)+1+0x83;for(int n=0;n<5;n++)sum+=Byte.toUnsignedInt(b[n]);b[5]=(byte)sum;return b;
    }
    private Map<String,Object> transition(String name,int port,int state,int count,byte[] old,byte[] now,
            int wantState,int wantCount,int wantPower,int wantReduction,int wantProtocol,boolean insertion)throws Exception{
        return transitionSeed(name,port,state,count,old,now,wantState,wantCount,wantPower,wantReduction,wantProtocol,insertion,Byte.toUnsignedInt(old[1])*10,Byte.toUnsignedInt(old[0]));
    }
    private Map<String,Object> transitionSeed(String name,int port,int state,int count,byte[] old,byte[] now,
            int wantState,int wantCount,int wantPower,int wantReduction,int wantProtocol,boolean insertion,int priorPower,int priorProtocol)throws Exception{
        EmulatorHelper e=fixture();long first=steps;
        try{
            long stateAt=0x2000cf22L+port,counterAt=BASE+0x1c+2*port,powerAt=BASE+0x30+4*port;
            e.writeMemory(toAddr(stateAt),new byte[]{(byte)state});write16(e,counterAt,count);
            write16(e,powerAt,priorPower);e.writeMemory(toAddr(powerAt+2),new byte[]{0x55,(byte)priorProtocol});
            e.writeMemory(toAddr(CACHE+6*port),old);e.writeMemory(toAddr(STACK+0x20),now);
            byte[] before=e.readMemory(toAddr(MEMORY),0x180),expected=before.clone();
            byte[] cacheBefore=e.readMemory(toAddr(CACHE-8),32),flagsBefore=e.readMemory(toAddr(FLAGS-8),24);
            e.writeRegister("r4",port);e.writeRegister("r5",BASE+0x58+port*0x12);e.writeRegister("r7",BASE+0x12+port*5);e.writeRegister("r8",BASE);
            e.writeRegister(e.getPCRegister(),0x40a81cL);execute(e,0x40a82eL,port);
            expected[(int)(stateAt-MEMORY)]=(byte)wantState;put16(expected,(int)(counterAt-MEMORY),wantCount);
            put16(expected,(int)(powerAt-MEMORY),wantPower);expected[(int)(powerAt+2-MEMORY)]=(byte)wantReduction;expected[(int)(powerAt+3-MEMORY)]=(byte)wantProtocol;
            if(insertion)put32(expected,(int)(BASE+0x44+4*port-MEMORY),1);
            require(Arrays.equals(e.readMemory(toAddr(MEMORY),expected.length),expected),name+": transition context/guards mismatch");
            require(Arrays.equals(e.readMemory(toAddr(CACHE-8),32),cacheBefore),name+": transition changed current-cache too soon");
            require(Arrays.equals(e.readMemory(toAddr(FLAGS-8),24),flagsBefore),name+": unexpected transition event flags");
            // The real worker commits current protocol only after the settling
            // block and telemetry calls. Execute this original updater separately.
            e.writeRegister("r0",port);e.writeRegister("r1",STACK+0x20);e.writeRegister("lr",RETURN|1);e.writeRegister(e.getPCRegister(),0x405e5cL);
            execute(e,RETURN,port);
            boolean changed=!Arrays.equals(old,now);
            byte[] cacheExpected=cacheBefore.clone();System.arraycopy(now,0,cacheExpected,8+6*port,6);
            require(Arrays.equals(e.readMemory(toAddr(CACHE-8),32),cacheExpected),name+": cache write or guards mismatch");
            byte[] flagsExpected=flagsBefore.clone();
            if(changed&&wantState==1)expected[(int)(BASE+port-MEMORY)]=1;
            if(changed&&wantState!=1){put16(flagsExpected,8,0x20<<port);put16(flagsExpected,10,0x20<<port);}
            require(Arrays.equals(e.readMemory(toAddr(MEMORY),expected.length),expected),name+": updater context/guards mismatch");
            require(Arrays.equals(e.readMemory(toAddr(FLAGS-8),24),flagsExpected),name+": deferred/immediate event flags mismatch");
            Map<String,Object> row=new LinkedHashMap<>();row.put("name",name);row.put("port",port);row.put("prior_state",state);row.put("prior_counter",count);row.put("old_cached_packet",HexFormat.of().formatHex(old));row.put("current_packet",HexFormat.of().formatHex(now));row.put("state",wantState);row.put("counter",wantCount);row.put("power_internal",wantPower);row.put("reduction",wantReduction);row.put("stored_protocol",wantProtocol);row.put("current_packet_committed_after_transition",true);row.put("context_and_guards_match",true);row.put("instruction_steps",steps-first);return row;
        }finally{e.dispose();}
    }
    private Map<String,Object> reduction(int port,int protocol)throws Exception{
        EmulatorHelper e=fixture();long first=steps;
        try{
            long powerAt=BASE+0x30+4*port;e.writeMemory(toAddr(0x2000cf22L+port),new byte[]{2});write16(e,powerAt,123);e.writeMemory(toAddr(powerAt+2),new byte[]{0x55,0x66});
            byte[] expected=e.readMemory(toAddr(MEMORY),0x180);put16(expected,(int)(powerAt-MEMORY),345);
            int[] table={5,5,5,4,4,4,5,1,3,2,8};int want=protocol<=10&&protocol!=6?table[protocol]:0x55;
            expected[(int)(powerAt+2-MEMORY)]=(byte)want;expected[(int)(powerAt+3-MEMORY)]=(byte)protocol;
            e.writeRegister("r0",port);e.writeRegister("r1",345);e.writeRegister("r2",protocol);e.writeRegister(e.getPCRegister(),0x409d08L);execute(e,RETURN,port);
            require(Arrays.equals(e.readMemory(toAddr(MEMORY),expected.length),expected),"Reduction context/guards mismatch enum "+protocol);
            Map<String,Object> row=new LinkedHashMap<>();row.put("name","all_native_protocol_reduction_values");row.put("port",port);row.put("protocol",protocol);row.put("prior_reduction",0x55);row.put("reduction",want);row.put("power_internal",345);row.put("context_and_guards_match",true);row.put("instruction_steps",steps-first);return row;
        }finally{e.dispose();}
    }
    public void run()throws Exception{
        require(SHA.equals(currentProgram.getExecutableSHA256()),"Wrong raw image");String[] args=getScriptArgs();require(args.length==1,"Expected new output directory");Path out=Paths.get(args[0]);require(!Files.exists(out),"Output must be new");Files.createDirectories(out);
        Gson json=new Gson();int cases=0;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)){
            for(int p=0;p<2;p++){
                List<Map<String,Object>> rows=new ArrayList<>();byte[] stable=packet(p,7,30,0x2717,3),zero=new byte[6];
                rows.add(transition("zero_before_threshold",p,2,18,stable,zero,2,19,300,0x55,7,false));
                rows.add(transition("zero_at_threshold",p,2,19,stable,zero,0,0,0,0,7,false));
                rows.add(transition("shared_counter_one_zero_during_settling",p,1,29,stable,zero,0,0,0,0,7,false));
                rows.add(transition("same_enum_before_settle",p,1,28,stable,stable,1,29,300,0x55,7,false));
                rows.add(transition("same_enum_at_settle",p,1,29,stable,stable,2,0,300,1,7,false));
                rows.add(transition("changed_enum_resets_settle",p,1,29,stable,packet(p,8,40,0x2717,3),1,0,300,0x55,7,false));
                rows.add(transition("unchanged_settled_packet",p,2,0,stable,stable,2,0,300,0x55,7,false));
                rows.add(transition("new_attachment_enters_state1",p,0,0,zero,stable,1,0,100,0x55,0,true));
                for(int field=1;field<=4;field++){
                    byte[] changed=stable.clone();changed[field]++;int sum=2*(p==0?0x92:0x94)+1+0x83;for(int n=0;n<5;n++)sum+=Byte.toUnsignedInt(changed[n]);changed[5]=(byte)sum;
                    rows.add(transition("metadata_field_"+field+"_settled_to1",p,2,0,stable,changed,1,0,300,0x55,7,false));
                    rows.add(transition("metadata_field_"+field+"_jitter_still_settles",p,1,29,stable,changed,2,0,300,1,7,false));
                }
                for(int code=3;code<=6;code++){
                    byte[] special=packet(p,code,40,0x2717,3);
                    rows.add(transition("special_enum_"+code+"_consumes_old_snapshot",p,1,12,stable,special,2,0,300,1,7,false));
                    rows.add(transitionSeed("special_enum_"+code+"_next_poll_refresh",p,2,0,special,special,2,0,400,code==6?0x55:4,code,false,300,7));
                }
                for(var row:rows){w.write(json.toJson(row));w.newLine();cases++;}
                for(int code=0;code<256;code++){w.write(json.toJson(reduction(p,code)));w.newLine();cases++;}
            }
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)){
            for(long pc:visited){var ins=getInstructionAt(toAddr(pc));require(ins!=null,"Missing original instruction "+Long.toHexString(pc));Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}
        }
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("cases",cases);meta.put("instruction_steps",steps);meta.put("mode_callbacks",modeCallbacks);meta.put("distinct_executed_instructions",visited.size());meta.put("all_expected_results_match",true);meta.put("stub_calls",stubs);
        meta.put("scope","Both ports: isolated original settling block 40a81c..40a82e with tail branches40a89a..40a902; actual transition409c1c, snapshot4053ac, comparison409bec, power409d08, initial-state4054ee. Separately executes original405e5c cache updater in worker order. Covers threshold edges, shared-counter zero, changed enum, each metadata byte, ongoing metadata jitter, special enums3..6 previous-snapshot consumption and all256 reduction enum inputs. Entire context and adjacent cache/event guards asserted.");
        meta.put("limits",new String[]{"No full worker/bus/checksum reader execution; entry assumes accepted current six-byte record and initialized registers","memcmp replaced by exact six-byte equality, bodies not independently emulated","logger and delay bodies stubbed; insertion timestamp helper replaced by fixed timestamp1","No telemetry accumulator/PFC/allocator/scheduler/ROM or physical negotiation executes","No sequential multi-poll timeline: boundary fixtures initialize explicit prior state/counter/cache","State numbers0/1/2 are internal host states, not named charging protocols","Checksum bytes recomputed for metadata mutations; no checksum-only physically valid packet asserted","Original full-worker copy/0x83 failure-order proof remains stage27"});
        meta.put("emulator_workaround","Instance-local fixed-Thumb setISAMode callback replacement; rejects ARM transitions, preserves original instruction p-code and firmware bytes.");Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);
        println("CUKTECH HUSB settling: "+cases+" fixtures / "+steps+" original steps");
    }
}
