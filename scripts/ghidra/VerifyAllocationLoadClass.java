// AD1204 0073 original AI load classifier and immediate revocation helper.
// Arg: NEW output directory. Synthetic RAM and scripted external observations only.
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
 * Checks the original AI load classifier and the immediate revocation helper on both ports.
 * Current power, peak, brand and other external values come from scripted stubs.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-allocation-load-class}</li>
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
public class VerifyAllocationLoadClass extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private static final long BASE=0x2000ce98L, MANAGER=0x2000cea8L, HUSB=0x2000cf28L;
    private long steps,callbacks; private final TreeSet<Long> visited=new TreeSet<>();
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
    private int off(long address){return Math.toIntExact(address-BASE);}
    private void b(byte[] data,long address,int value){data[off(address)]=(byte)value;}
    private void h(byte[] data,long address,int value){b(data,address,value);b(data,address+1,value>>>8);}
    private static int classify(int old,int state,int power,int reduction,int destination,int peak,int current,int brand,int count,int otherPower){
        if(state!=2||power==0)return old;
        boolean eligible=reduction==5||((reduction==1||(brand==2&&reduction==8))&&power<=270);
        if(old==0){
            if(eligible&&destination<=9200&&peak<20)return count==1&&otherPower==0?1:3;
            if(reduction==5||((reduction==1||(brand==2&&reduction==8))&&power<=220&&destination<=9200))return 3;
            return 0;
        }
        if(current<30&&destination<=9200){
            if(old>=3&&eligible&&peak<20&&count==1&&otherPower==0)return 1;
            return old;
        }
        return power<=220&&destination<=9200?3:0;
    }
    private Map<String,Object> check(String label,boolean immediate,int[] state,int[] old,int[] power,int[] reduction,int[] destination,int[] peak,int[] current,int[] brand,int count) throws Exception {
        EmulatorHelper e=fixture();long begin=steps;int iterations=0,memcmpCalls=0,currentCalls=0,peakCalls=0,brandCalls=0;int[] expected=old.clone();boolean selected=false;
        if(immediate){
            for(int p=0;p<2;p++)if(state[p]==2&&power[p]!=0&&old[p]!=0&&(current[p]>=30||destination[p]>9200)){expected[p]=power[p]<=220&&destination[p]<=9200?3:0;selected=true;break;}
        }else for(int p=0;p<2;p++)expected[p]=classify(old[p],state[p],power[p],reduction[p],destination[p],peak[p],current[p],brand[p],count,power[1-p]);
        boolean changed=!Arrays.equals(old,expected);int expectedReturn=immediate?(selected?4:2):(changed?4:2);
        byte[] context=new byte[0x160];Arrays.fill(context,(byte)0x6b);b(context,MANAGER+0xb,count);
        for(int p=0;p<2;p++){b(context,MANAGER+0x7a+p,state[p]);b(context,MANAGER+0x70+p,old[p]);h(context,HUSB+0x30+4*p,power[p]);b(context,HUSB+0x32+4*p,reduction[p]);h(context,HUSB+0x62+18*p,destination[p]);}
        byte[] wanted=context.clone();for(int p=0;p<2;p++)b(wanted,MANAGER+0x70+p,expected[p]);
        long entry=immediate?0x406db4L:0x406b78L,stop=immediate?(selected?0x406e22L:0x406e00L):0x406da2L;
        try{
            e.writeMemory(toAddr(BASE),context);e.writeRegister(e.getPCRegister(),entry);
            while(true){monitor.checkCancelled();if(++iterations>900)throw new IllegalStateException("Runaway classifier "+label);long pc=e.getExecutionAddress().getOffset();if(pc==stop)break;
                if(pc==0x405d70L||pc==0x405d24L||pc==0x406364L||pc==0x405cfcL){int p=r(e,0);if(p<0||p>1)throw new IllegalStateException("Invalid helper port "+p);if(pc==0x405d70L){currentCalls++;ret(e,current[p]);}else if(pc==0x405d24L){peakCalls++;ret(e,peak[p]);}else if(pc==0x406364L){brandCalls++;ret(e,brand[p]);}else ret(e,0);continue;}
                if(pc==0x403234L){int length=r(e,2);if(length!=5)throw new IllegalStateException("Unexpected comparison size");byte[] a=e.readMemory(toAddr(Integer.toUnsignedLong(r(e,0))),length),z=e.readMemory(toAddr(Integer.toUnsignedLong(r(e,1))),length);int value=0;for(int n=0;n<length;n++)if(a[n]!=z[n]){value=Byte.toUnsignedInt(a[n])-Byte.toUnsignedInt(z[n]);break;}memcmpCalls++;ret(e,value);continue;}
                if(pc==0x4054feL||pc==0x4051b6L||pc==0x4239b8L){ret(e,0);continue;}
                if((immediate&&(pc<0x406db4L||pc>=0x406e24L))||(!immediate&&(pc<0x406b78L||pc>=0x406da4L)))throw new IllegalStateException("Escaped classifier "+Long.toHexString(pc));
                visited.add(pc);if(!e.step(monitor))throw new IllegalStateException(e.getLastError());steps++;
            }
            byte[] actual=e.readMemory(toAddr(BASE),context.length);
            if(r(e,0)!=expectedReturn||!Arrays.equals(actual,wanted)||memcmpCalls!=(immediate?0:1))throw new IllegalStateException("Classifier mismatch "+label+" expected="+Arrays.toString(expected)+" actual="+Byte.toUnsignedInt(actual[off(MANAGER+0x70)])+","+Byte.toUnsignedInt(actual[off(MANAGER+0x71)])+" return="+r(e,0)+" expectedReturn="+expectedReturn);
            Map<String,Object> row=new LinkedHashMap<>();row.put("label",label);row.put("entry",String.format("%08x",entry));row.put("host_state",state);row.put("initial_load_class",old);row.put("power_hint_units_0_1w",power);row.put("reduction_class",reduction);row.put("destination_voltage_word",destination);row.put("rolling_peak_units_0_1w",peak);row.put("current_power_units_0_1w",current);row.put("scripted_brand_class",brand);row.put("active_count",count);row.put("expected_load_class",expected);row.put("expected_return",expectedReturn);row.put("load_bytes_changed",changed);row.put("immediate_candidate_selected",immediate?selected:null);row.put("current_power_calls",currentCalls);row.put("rolling_peak_calls",peakCalls);row.put("brand_calls",brandCalls);row.put("memcmp_calls",memcmpCalls);row.put("entire_context_and_guards_match",true);row.put("instruction_steps",steps-begin);return row;
        }finally{e.dispose();}
    }
    private int[] pair(int port,int value,int other){int[] a={other,other};a[port]=value;return a;}
    public void run() throws Exception {
        if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);Gson json=new Gson();int count=0;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)){
            for(int p=0;p<2;p++)for(int reduction:new int[]{1,2,3,5,8})for(int brand:new int[]{0,2})for(int power:new int[]{220,221,270,271})for(int dest:new int[]{9200,9201})for(int peak:new int[]{19,20}){
                w.write(json.toJson(check("initial",false,pair(p,2,0),new int[]{0,0},pair(p,power,0),pair(p,reduction,0),pair(p,dest,0),pair(p,peak,0),pair(p,29,0),pair(p,brand,0),1)));w.newLine();count++;
            }
            for(int p=0;p<2;p++)for(int old:new int[]{1,3})for(int reduction:new int[]{1,2,3,5,8})for(int brand:new int[]{0,2})for(int power:new int[]{220,221,270,271})for(int dest:new int[]{9200,9201})for(int current:new int[]{29,30}){
                w.write(json.toJson(check("existing",false,pair(p,2,0),pair(p,old,0),pair(p,power,0),pair(p,reduction,0),pair(p,dest,0),pair(p,19,0),pair(p,current,0),pair(p,brand,0),1)));w.newLine();count++;
            }
            for(int p=0;p<2;p++)for(int state:new int[]{0,1})for(int old:new int[]{0,1,3}){
                w.write(json.toJson(check("host_state_gate",false,pair(p,state,0),pair(p,old,0),pair(p,220,0),pair(p,1,0),pair(p,9200,0),pair(p,19,0),pair(p,30,0),new int[]{0,0},1)));w.newLine();count++;
            }
            for(int p=0;p<2;p++)for(int old:new int[]{0,1,3}){
                w.write(json.toJson(check("zero_hint_gate",false,pair(p,2,0),pair(p,old,0),new int[]{0,0},pair(p,5,0),pair(p,9200,0),pair(p,19,0),pair(p,30,0),new int[]{0,0},1)));w.newLine();count++;
            }
            for(int p=0;p<2;p++)for(int old:new int[]{0,3})for(int other:new int[]{0,100})for(int active:new int[]{1,2}){
                w.write(json.toJson(check("other_port_and_count_gate",false,pair(p,2,0),pair(p,old,0),pair(p,220,other),pair(p,1,0),pair(p,9200,0),pair(p,19,0),pair(p,29,0),new int[]{0,0},active)));w.newLine();count++;
            }
            for(int p=0;p<2;p++)for(int state:new int[]{0,1,2})for(int old:new int[]{0,1,3})for(int power:new int[]{0,220,221})for(int dest:new int[]{9200,9201})for(int current:new int[]{29,30}){
                w.write(json.toJson(check("immediate",true,pair(p,state,0),pair(p,old,0),pair(p,power,0),pair(p,1,0),pair(p,dest,0),new int[]{0,0},pair(p,current,0),new int[]{0,0},1)));w.newLine();count++;
            }
            for(boolean immediate:new boolean[]{false,true})for(int old:new int[]{1,3})for(int power:new int[]{220,221}){
                w.write(json.toJson(check("both_ports_eligible",immediate,new int[]{2,2},new int[]{old,old},new int[]{power,power},new int[]{1,1},new int[]{9200,9200},new int[]{19,19},new int[]{30,30},new int[]{0,0},2)));w.newLine();count++;
            }
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)){for(long pc:visited){var ins=getInstructionAt(toAddr(pc));if(ins==null)throw new IllegalStateException("No instruction at "+Long.toHexString(pc));Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("cases",count);meta.put("instruction_steps",steps);meta.put("distinct_executed_instructions",visited.size());meta.put("mode_callbacks",callbacks);meta.put("all_expected_results_match",true);meta.put("entries",new String[]{"00406b78","00406db4"});meta.put("stops",new String[]{"00406da2 before POP","00406e00 before POP","00406e22 before POP"});
        meta.put("scope","Original classifier and immediate revocation instructions on both ports. Synthetic host states, power hints, reduction classes1/2/3/5/8, brand0/Apple2, destination boundary9200/9201, peak19/20,current29/30 and load0/1/3. Full context and guards compared; only expected load bytes may change. Original BL executes before helper stubs. Scripted current power, peak, brand and logging; exact five-byte memcmp semantics. Does not execute telemetry scaling/history production, VID classification, scheduler, scene allocation, peripheral or bus code. Immediate helper returns4 after selecting a candidate even when rewritten load value is unchanged. Instance-local fixed-Thumb callback workaround changes no original instruction/p-code.");
        Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH allocation load class: "+count+" cases / "+steps+" original steps");
    }
}
