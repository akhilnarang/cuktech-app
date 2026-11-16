// Execute original 0073 allocation instructions with synthetic RAM inputs.
// Argument: a new output directory. No bus, ROM, charger or cloud access.
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
 * Checks the original allocation dispatcher, the scenes, the shared register and flag helpers,
 * the first-insert comparator, the code-to-power function and the current-cap getter. Expected
 * rows are transcribed independently only for the fixed normal scenes and selected AI boundaries.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-allocation}</li>
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
public class VerifyAllocation extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private static final long OUT=0x20070020L,CTX=0x2000cea8L;
    private static final long[] SCENES={0x407104L,0x407508L,0x407750L,0x4079d0L,0x407af8L,0x407bf4L,0x407d1cL,0x407e70L,0x407fbcL,0x408180L,0x408298L,0x4083a0L};
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
    private void ret(EmulatorHelper e,int value){long next=e.readRegister("lr").longValue()&~1L;e.writeRegister("r0",Integer.toUnsignedLong(value));e.writeRegister(e.getPCRegister(),next);}
    private void byteAt(EmulatorHelper e,long address,int value){e.writeMemory(toAddr(address),new byte[]{(byte)value});}
    private void word(EmulatorHelper e,long address,int value){e.writeMemory(toAddr(address),new byte[]{(byte)value,(byte)(value>>8),(byte)(value>>16),(byte)(value>>24)});}
    private void half(EmulatorHelper e,long address,int value){e.writeMemory(toAddr(address),new byte[]{(byte)value,(byte)(value>>8)});}
    private int[] values(byte[] data){int[] result=new int[data.length];for(int n=0;n<data.length;n++)result[n]=Byte.toUnsignedInt(data[n]);return result;}
    private Map<String,Object> runCase(long entry,int scene,int mask,int ac,int hardware,int budget,int mode,int enabled,int p1,int p2,int reduction1,int reduction2,int native1,int native2,int dest1,int dest2,int load1,int load2,int first,int[] expected) throws Exception {
        EmulatorHelper e=fixture();long begin=steps;int loops=0;byte[] beforeClamp=null;String path="RAW";
        try{
            e.writeMemory(toAddr(CTX),new byte[0x160]);e.writeMemory(toAddr(0x2000c998L),new byte[24]);e.writeMemory(toAddr(0x2000ec18L),new byte[32]);
            byte[] guards=new byte[36];Arrays.fill(guards,(byte)0x5a);e.writeMemory(toAddr(OUT-16),guards);e.writeMemory(toAddr(OUT),new byte[]{11,11,(byte)0x80,0x70});
            // Original startup profile/enable rows, asserted against the initialized project.
            byte[] startup={11,11,(byte)0x80,0x70,0x60,11,11,(byte)0x80,0x70,0x60};
            if(!Arrays.equals(getBytes(toAddr(0x2000c2b6L),10),startup))throw new IllegalStateException("Unexpected startup rows");
            e.writeMemory(toAddr(0x2000c2b6L),startup);
            byteAt(e,CTX+10,ac);byteAt(e,CTX+11,Integer.bitCount(mask));byteAt(e,CTX+0x1b,scene);byteAt(e,CTX+0x70,load1);byteAt(e,CTX+0x71,load2);
            word(e,0x2000cf6cL,first==0?1:2);word(e,0x2000cf70L,first==0?2:1);
            int sum=0;
            for(int port=0;port<4;port++){
                boolean busy=(mask&(1<<port))!=0;int power=busy?(port==0?p1:port==1?p2:100):0;sum+=power;
                byteAt(e,CTX+0x7a+port,busy?2:0);half(e,0x2000cf58L+port*4,power);
                byteAt(e,0x2000ec1cL+port*8,busy?1:0);byteAt(e,0x2000c2bbL+port,(enabled&(1<<port))!=0?Byte.toUnsignedInt(startup[5+port]):0);
                if(port<2){byteAt(e,0x2000cf5aL+port*4,port==0?reduction1:reduction2);byteAt(e,0x2000c998L+port*6,port==0?native1:native2);half(e,0x2000cf8aL+port*0x12,port==0?dest1:dest2);}
            }
            e.writeRegister("r0",OUT);e.writeRegister("r1",mode);e.writeRegister("r2",(long)(budget-sum));e.writeRegister("r3",budget);e.writeRegister(e.getPCRegister(),entry);
            while(true){monitor.checkCancelled();if(++loops>2500)throw new IllegalStateException("Runaway allocation");long pc=e.getExecutionAddress().getOffset();if(pc==0x40306aL)break;
                if(pc==0x407004L)beforeClamp=e.readMemory(toAddr(OUT),4);
                for(long s:SCENES)if(pc==s)path=String.format("%08x",s);
                if(pc==0x4239b8L||pc==0x4051b6L||pc==0x424dc0L){ret(e,0);continue;}
                if(pc==0x417d60L){ret(e,hardware);continue;}
                if(pc==0x415d2cL){ret(e,1);continue;}
                if(!((pc>=0x406e30L&&pc<0x4084c8L)||(pc>=0x4052d2L&&pc<0x4057c4L)||(pc>=0x4092e0L&&pc<0x4093bcL)||(pc>=0x409078L&&pc<0x40909eL)))throw new IllegalStateException("Escaped allocation at "+Long.toHexString(pc));
                visited.add(pc);if(!e.step(monitor))throw new IllegalStateException(e.getLastError()+" at "+Long.toHexString(pc));steps++;
            }
            int[] output=values(e.readMemory(toAddr(OUT),4));
            byte[] after=e.readMemory(toAddr(OUT-16),36);for(int n=0;n<36;n++)if((n<16||n>=20)&&after[n]!=(byte)0x5a)throw new IllegalStateException("Output guard changed");
            if(entry==0x406e30L){
                int need=0;int[] caps={1200,1200,450,330};for(int n=0;n<4;n++)if((mask&(1<<n))==0&&(mode==0||(enabled&(1<<n))!=0))need=Math.max(need,caps[n]);
                boolean useScene=budget-sum<need||((mask&3)==3)||(enabled!=15&&mask!=0);
                long wantedEntry=budget>900?new long[]{0x407104L,0x4079d0L,0x408180L,0x407d1cL}[scene-1]:
                    hardware!=0&&ac==0?new long[]{0x407508L,0x407af8L,0x408298L,0x407e70L}[scene-1]:new long[]{0x407750L,0x407bf4L,0x4083a0L,0x407fbcL}[scene-1];
                if(!path.equals(useScene?String.format("%08x",wantedEntry):"RAW"))throw new IllegalStateException("Dispatcher path mismatch");
                if(beforeClamp==null)throw new IllegalStateException("Missing final clamp");int[] wanted=values(beforeClamp);
                if(ac==0)for(int n=0;n<4;n++)wanted[n]=switch(wanted[n]){case 4->hardware==0?3:4;case 6->hardware==0?5:6;case 7->6;case 9,10->8;case 11->10;default->wanted[n];};
                if(!Arrays.equals(wanted,output))throw new IllegalStateException("Final clamp mismatch");
                if(mode==1)for(int n=0;n<4;n++)if((enabled&(1<<n))==0&&output[n]!=0)throw new IllegalStateException("Disabled cap nonzero");
                int stored=Byte.toUnsignedInt(e.readMemory(toAddr(CTX+0x24),1)[0])|(Byte.toUnsignedInt(e.readMemory(toAddr(CTX+0x25),1)[0])<<8);if(stored!=((budget-sum)&65535))throw new IllegalStateException("Remaining budget not stored");
            }
            if(expected!=null&&!Arrays.equals(expected,output))throw new IllegalStateException("Independent table mismatch entry="+Long.toHexString(entry)+",mask="+mask+",actual="+Arrays.toString(output)+",expected="+Arrays.toString(expected));
            Map<String,Object> row=new LinkedHashMap<>();row.put("entry",String.format("%08x",entry));row.put("scene",scene);row.put("occupied_mask",mask);row.put("ac_selector",ac);row.put("hardware_flag",hardware);row.put("budget_deciwatts",budget);row.put("port_mode",mode);row.put("enabled_mask",enabled);row.put("power_hints_deciwatts",new int[]{p1,p2});row.put("reduction_classes",new int[]{reduction1,reduction2});row.put("native_enums",new int[]{native1,native2});row.put("destination_words",new int[]{dest1,dest2});row.put("input_load_classes",new int[]{load1,load2});row.put("first_insert_return",first);row.put("scene_entry",path);row.put("before_final_clamp",beforeClamp==null?null:values(beforeClamp));row.put("caps",output);row.put("output_load_classes",values(e.readMemory(toAddr(CTX+0x70),2)));row.put("independent_expected_row",expected!=null);row.put("instruction_steps",steps-begin);return row;
        }finally{e.dispose();}
    }
    public void run() throws Exception {
        if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image");Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);Gson json=new Gson();int count=0,independent=0;
        int[][] apple={{},{11,3,128,96},{7,11,128,96},{7,3,96,96},{7,7,128,48},{7,1,128,48},{7,7,128,48},{7,1,96,96},{10,10,48,112},{10,1,48,96},{7,10,48,96},{7,1,96,96},{10,10,48,48},{10,1,48,48},{10,10,48,48},{7,1,48,48}};
        int[][] single={{},{11,1,96,96},{10,11,96,96},{10,1,96,96},{10,10,128,48},{10,1,96,48},{7,10,96,48},{7,1,96,96},{10,10,48,112},{10,1,48,96},{7,10,48,96},{7,1,96,96},{10,10,48,48},{10,1,48,48},{7,10,48,48},{7,1,48,48}};
        int[][] balance={{},{11,4,128,96},{4,11,128,96},{4,4,96,96},{7,7,128,48},{7,3,128,48},{3,7,128,48},{3,3,96,48},{10,10,48,112},{10,3,48,96},{3,10,48,96},{3,3,48,96},{10,10,48,48},{10,3,48,48},{3,10,48,48},{3,3,48,48}};
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)){
            for(int scene=2;scene<=4;scene++)for(int mask=1;mask<16;mask++){
                int[] expected=(scene==2?apple:scene==3?single:balance)[mask];long entry=scene==2?0x4079d0L:scene==3?0x408180L:0x407d1cL;
                w.write(json.toJson(runCase(entry,scene,mask,2,0,1200,0,15,100,100,1,1,7,7,9000,9000,0,0,0,expected)));w.newLine();count++;independent++;
            }
            for(int scene=1;scene<=4;scene++)for(int mask=0;mask<16;mask++)for(int ac=0;ac<=2;ac++)for(int hardware=0;hardware<=1;hardware++)for(int budget:new int[]{900,1200}){
                w.write(json.toJson(runCase(0x406e30L,scene,mask,ac,hardware,budget,0,15,100,100,1,1,7,7,9000,9000,0,0,0,null)));w.newLine();count++;
            }
            // User-defined enable masks: all 16 masks at all four scenes.
            for(int scene=1;scene<=4;scene++)for(int enabled=0;enabled<16;enabled++){
                w.write(json.toJson(runCase(0x406e30L,scene,3,1,0,1200,1,enabled,270,600,1,3,7,8,9000,9000,0,0,0,null)));w.newLine();count++;
            }
            // Independent AI two-C boundary/class/priority cases, selector2.
            for(int first=0;first<2;first++)for(int p1:new int[]{270,649,650,660})for(int p2:new int[]{270,649,650,660}){
                boolean h1=p1>=650,h2=p2>=650;boolean c1=(h1&&!h2)||((h1==h2)&&((first==1)^h1));int[] expected={c1?7:3,c1?3:7,96,96};
                w.write(json.toJson(runCase(0x407104L,1,3,2,0,1200,0,15,p1,p2,1,1,7,7,9000,9000,0,0,first,expected)));w.newLine();count++;independent++;
            }
            for(int l1:new int[]{0,1,2,3,4})for(int l2:new int[]{0,1,2,3,4})if(l1!=0||l2!=0){int[] expected=l1!=0?new int[]{1,l1>=3?10:11,96,96}:new int[]{l2>=3?10:11,1,96,96};
                w.write(json.toJson(runCase(0x407104L,1,3,2,0,1200,0,15,270,270,1,1,7,7,9000,9000,l1,l2,0,expected)));w.newLine();count++;independent++;
            }
            // Native enum8 and destination19V are a separate high-power predicate.
            for(int reduction:new int[]{1,2,3,5,8})for(int nativeEnum:new int[]{7,8,9})for(int dest:new int[]{18999,19000})for(int power:new int[]{649,650}){
                boolean high=(reduction==1&&power>=650)||(nativeEnum==8&&dest>=19000);int[] expected={high?7:3,high?3:7,96,96};
                w.write(json.toJson(runCase(0x407104L,1,3,2,0,1200,0,15,power,270,reduction,1,nativeEnum,7,dest,9000,0,0,0,expected)));w.newLine();count++;independent++;
            }
            // Balance AC-low three-port branch: class1 and >=30W, then insertion order.
            for(int mask:new int[]{7,11})for(int first=0;first<2;first++)for(int r1:new int[]{1,3})for(int r2:new int[]{1,3})for(int p1:new int[]{299,300})for(int p2:new int[]{299,300}){
                boolean h1=r1==1&&p1>=300,h2=r2==1&&p2>=300;boolean c1=(h1&&!h2)||((h1==h2)&&((first==1)^h1));int[] expected={c1?2:1,c1?1:2,160,160};
                w.write(json.toJson(runCase(0x407e70L,4,mask,0,1,900,0,15,p1,p2,r1,r2,7,7,9000,9000,0,0,first,expected)));w.newLine();count++;independent++;
            }
            w.write(json.toJson(runCase(0x406e30L,1,3,1,0,1200,0,15,270,600,1,3,7,8,9000,8500,0,0,0,new int[]{4,7,96,96})));w.newLine();count++;independent++;
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)){for(long pc:visited){var ins=getInstructionAt(toAddr(pc));if(ins==null){clearListing(toAddr(pc),toAddr(pc));new ArmDisassembleCommand(toAddr(pc),null,true).applyTo(currentProgram,monitor);ins=getInstructionAt(toAddr(pc));}if(ins==null)throw new IllegalStateException("No instruction at "+Long.toHexString(pc));Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}}
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("cases",count);meta.put("independent_expected_rows",independent);meta.put("instruction_steps",steps);meta.put("distinct_executed_instructions",visited.size());meta.put("mode_callbacks",callbacks);meta.put("all_checks_passed",true);
        meta.put("scope","Original allocation dispatcher, scenes, shared register/flag helpers, first-insert comparator, code-to-power and current-cap getter. Synthetic occupied masks, host/power/native cache, AC selectors0/1/2, hardware0/1 and1200/900 budgets. Matrix outputs recorded; independently transcribed expected rows only for fixed normal scenes and selected AI boundaries/classes. Every dispatcher fixture independently checks its final clamp, disabled-port zeroing, remaining-budget store and output guards. Logger/delay bodies stubbed, hardware getter scripted, timer returns1; no peripheral/ROM/scheduler/manager/classifier execution, physical negotiation or ACK. Fixed-Thumb instance workaround changes no original bytes/p-code.");
        Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);println("Allocation verification: "+count+" cases, "+independent+" independent rows, "+steps+" original steps");
    }
}
