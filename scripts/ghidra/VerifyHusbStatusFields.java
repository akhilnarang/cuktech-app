// Original HUSB362 poll worker with synthetic SRAM and scripted external calls.
// Arg: NEW output directory. Does not execute physical bus, ROM or peripherals.
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
 * Checks the original HUSB362 poll worker. External calls are scripted stubs.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-husb-status-fields}</li>
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
public class VerifyHusbStatusFields extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private static final long STACK=0x2007c000L, BASE=0x2000cf28L, MEMORY=0x2000ce98L;
    private static final int POISON=0xa7;
    private long totalSteps,modeCallbacks;
    private final TreeSet<Long> visited=new TreeSet<>();
    private final Map<String,Long> stubCounts=new TreeMap<>();
    @SuppressWarnings("unchecked")
    private EmulatorHelper fixture() throws Exception {
        EmulatorHelper emu=new EmulatorHelper(currentProgram);
        // Instance-local workaround, as in VerifyScLimitCache. Original p-code
        // and bytes remain unchanged; any ARM-mode transition is rejected.
        var outer=emu.getEmulator().getClass().getDeclaredField("emulator");outer.setAccessible(true);
        Emulate engine=(Emulate)outer.get(emu.getEmulator());
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
        if(!replaced)throw new IllegalStateException("Expected ARM setISAMode handler not found");
        for(int n=0;n<13;n++)emu.writeRegister("r"+n,0);
        for(String flag:new String[]{"CY","OV","NG","ZR"})emu.writeRegister(flag,0);
        emu.writeRegister("sp",STACK);emu.writeRegister("lr",0x40306bL);
        emu.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);
        return emu;
    }
    private int reg(EmulatorHelper emu,int n){return emu.readRegister("r"+n).intValue();}
    private int word(EmulatorHelper emu,long address)throws Exception {
        byte[] b=emu.readMemory(toAddr(address),4);
        return Byte.toUnsignedInt(b[0])|(Byte.toUnsignedInt(b[1])<<8)|(Byte.toUnsignedInt(b[2])<<16)|(Byte.toUnsignedInt(b[3])<<24);
    }
    private void stub(EmulatorHelper emu,String name,int result){
        stubCounts.merge(name,1L,Long::sum);
        long next=emu.readRegister("lr").longValue()&~1L;
        emu.writeRegister("r0",Integer.toUnsignedLong(result));emu.writeRegister(emu.getPCRegister(),next);
    }
    private static void put16(byte[] data,int offset,int value){data[offset]=(byte)value;data[offset+1]=(byte)(value>>8);}
    private static void require(boolean condition,String message){if(!condition)throw new IllegalStateException(message);}
    private Map<String,Object> poll(int port,int dest,int mode,boolean active,boolean response83Success)throws Exception {
        EmulatorHelper emu=fixture();long started=totalSteps;int iterations=0;
        int measured=dest==5499?20000:dest==5500?5000:12345,amps=1379,status=active?1:0;
        byte[] response=new byte[17];put16(response,0,measured);put16(response,2,amps);put16(response,4,status);
        put16(response,6,0x2468);put16(response,8,0x89ab);put16(response,10,dest);put16(response,12,0xcdef);put16(response,14,0x1357);
        int checksum=2*(port==0?0x92:0x94)+1+0x82;
        for(int i=0;i<16;i++)checksum+=Byte.toUnsignedInt(response[i]);response[16]=(byte)checksum;
        byte[] before=new byte[0x140];
        Arrays.fill(before,0,16,(byte)0x5a);Arrays.fill(before,before.length-16,before.length,(byte)0x5a);
        int cacheIndex=(int)(BASE+0x58+port*0x12-MEMORY);
        Arrays.fill(before,(int)(BASE+0x58-MEMORY),(int)(BASE+0x58+36-MEMORY),(byte)0xcc);
        before[(int)(BASE+0x12+port*5-MEMORY)]=7; // Allocation byte forwarded by original code.
        byte[] expected=before.clone();System.arraycopy(response,0,expected,cacheIndex,response.length);expected[cacheIndex+17]=(byte)POISON;
        if(!active)put16(expected,(int)(BASE+0x1c+port*2-MEMORY),1); // Original protocol-zero debounce increment.
        List<Integer> highPower=new ArrayList<>();List<List<Integer>> telemetry=new ArrayList<>();
        List<List<Integer>> aggregate=new ArrayList<>(),transition=new ArrayList<>();
        List<String> order=new ArrayList<>();List<Integer> protocolPayload=new ArrayList<>();
        int reads82=0,reads83=0,protocolUpdates=0,copies=0,sensorCalls=0;
        try {
            emu.writeMemory(toAddr(MEMORY),before);
            byte[] stack=new byte[0x240];Arrays.fill(stack,(byte)POISON);emu.writeMemory(toAddr(STACK-0x200),stack);
            emu.writeRegister("r0",port);emu.writeRegister(emu.getPCRegister(),0x40a718L);
            while(emu.getExecutionAddress().getOffset()!=0x40a85aL){
                monitor.checkCancelled();if(++iterations>500)throw new IllegalStateException("Poll fixture runaway");
                long pc=emu.getExecutionAddress().getOffset();
                if(pc==0x40a5f4L){require(reg(emu,0)==port,"Wrong reconcile port");stub(emu,"reconcile",0);continue;}
                if(pc==0x414c80L){
                    require(reg(emu,0)==port,"Wrong 0x82 port");
                    long target=Integer.toUnsignedLong(reg(emu,1));
                    // Deliberately write only 16 data bytes plus checksum. The
                    // next byte keeps the controlled stack-poison value.
                    emu.writeMemory(toAddr(target),response);reads82++;order.add("read82");stub(emu,"read82_scripted_success",1);continue;
                }
                if(pc==0x403154L){
                    require(reg(emu,2)==18,"Poll cache copy must be 18 bytes");
                    require(Integer.toUnsignedLong(reg(emu,0))==BASE+0x58+port*0x12,"Wrong raw cache destination");
                    emu.writeMemory(toAddr(Integer.toUnsignedLong(reg(emu,0))),emu.readMemory(toAddr(Integer.toUnsignedLong(reg(emu,1))),18));
                    copies++;order.add("copy18");stub(emu,"memcpy_bytecopy_18",0);continue;
                }
                if(pc==0x417d60L){stub(emu,"mode_getter",mode);continue;}
                if(pc==0x408eccL){require(mode==1&&reg(emu,0)==port,"Unexpected high-power reconcile");stub(emu,"high_power_reconcile",0);continue;}
                if(pc==0x409dd8L){require(reg(emu,0)==port,"Wrong high-power port");highPower.add(reg(emu,1));order.add("high_power");stub(emu,"high_power_setter",0);continue;}
                if(pc==0x417ba4L){stub(emu,"ui_mode_getter",0);continue;}
                if(pc==0x414dacL){
                    require(active&&reg(emu,0)==port,"Unexpected 0x83 read");reads83++;order.add("read83");
                    if(response83Success)emu.writeMemory(toAddr(Integer.toUnsignedLong(reg(emu,1))),new byte[]{3,30,0,0,0,0});
                    stub(emu,"read83_scripted_"+(response83Success?"success":"failure"),response83Success?1:0);continue;
                }
                if(pc==0x409c1cL){transition.add(Arrays.asList(reg(emu,0),reg(emu,1)));stub(emu,"protocol_state_transition",0);continue;}
                if(pc==0x414c70L){require(reg(emu,0)==0x2468,"Wrong sensor input");sensorCalls++;stub(emu,"sensor_lookup",73);continue;}
                if(pc==0x40a57cL){aggregate.add(Arrays.asList(reg(emu,0),reg(emu,1)));stub(emu,"aggregate_status_update",0);continue;}
                if(pc==0x405d88L){
                    long sp=emu.readRegister("sp").longValue();telemetry.add(Arrays.asList(reg(emu,0),reg(emu,1),reg(emu,2),reg(emu,3),word(emu,sp),word(emu,sp+4)));
                    order.add("telemetry");stub(emu,"telemetry_accumulator",0);continue;
                }
                if(pc==0x405e5cL){
                    require(reg(emu,0)==port,"Wrong protocol-cache port");protocolUpdates++;protocolPayload.clear();
                    for(byte b:emu.readMemory(toAddr(Integer.toUnsignedLong(reg(emu,1))),6))protocolPayload.add(Byte.toUnsignedInt(b));
                    order.add("protocol_cache");stub(emu,"protocol_cache_update",0);continue;
                }
                require(pc>=0x40a718L&&pc<0x40a904L,"Escaped original worker at "+Long.toHexString(pc));
                visited.add(pc);if(!emu.step(monitor))throw new IllegalStateException(emu.getLastError());totalSteps++;
            }
            boolean completed=!active||response83Success;
            List<Integer> expectedHigh=(mode==0&&!completed)?List.of():List.of(mode==1?(dest>5500?1:0):(active?1:0));
            require(highPower.equals(expectedHigh),"High-power decision/order mismatch");
            require(reads82==1&&copies==1&&reads83==(active?1:0),"Read/copy counts mismatch");
            require(Arrays.equals(emu.readMemory(toAddr(MEMORY),before.length),expected),"Raw cache/context/guards mismatch");
            require(protocolUpdates==(completed?1:0)&&sensorCalls==(completed?1:0),"Failed 0x83 must stop subsequent updates");
            require(telemetry.equals(completed?List.of(Arrays.asList(port,measured,amps,status,73,7)):List.of()),"Telemetry does not preserve measured V/I/status");
            require(aggregate.equals(completed?List.of(Arrays.asList(port,status)):List.of()),"Aggregate status mismatch");
            require(transition.equals(active&&response83Success?List.of(Arrays.asList(port,2)):List.of()),"Protocol-state callback mismatch");
            require(protocolPayload.equals(completed?(active?List.of(3,30,0,0,0,0):List.of(0,0,0,0,0,0)):List.of()),"Protocol payload mismatch");
            require(order.indexOf("copy18")>order.indexOf("read82"),"Raw cache must follow 0x82");
            if(active)require(order.indexOf("read83")>order.indexOf("copy18"),"Raw cache must precede 0x83 failure");
            Map<String,Object> row=new LinkedHashMap<>();row.put("port",port);row.put("destination_word",dest);row.put("measured_voltage_word",measured);row.put("measured_current_word",amps);row.put("mode_getter_result",mode);row.put("active",active);row.put("scripted_83_success",response83Success);
            row.put("read82_calls",reads82);row.put("read83_calls",reads83);row.put("raw_cache_hex",HexFormat.of().formatHex(emu.readMemory(toAddr(BASE+0x58+port*0x12),18)));row.put("checksum_byte",Byte.toUnsignedInt(response[16]));row.put("extra_cached_stack_byte",POISON);row.put("high_power_arguments",highPower);row.put("expected_high_power_arguments",expectedHigh);row.put("telemetry_arguments",telemetry);row.put("aggregate_status_arguments",aggregate);row.put("protocol_state_arguments",transition);row.put("protocol_cache_payload",protocolPayload);row.put("call_order",order);row.put("other_context_and_guards_preserved",true);row.put("instruction_steps",totalSteps-started);return row;
        }finally{emu.dispose();}
    }
    public void run()throws Exception {
        if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        String[] args=getScriptArgs();if(args.length!=1)throw new IllegalArgumentException("Expected new output directory");
        Path out=Paths.get(args[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);
        Gson json=new Gson();int count=0;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)){
            for(int port=0;port<2;port++)for(int dest:new int[]{5499,5500,5501})for(int mode=0;mode<2;mode++)for(boolean active:new boolean[]{false,true})for(boolean success:new boolean[]{false,true}){
                w.write(json.toJson(poll(port,dest,mode,active,success)));w.newLine();count++;
            }
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)){
            for(long pc:visited){var ins=getInstructionAt(toAddr(pc));if(ins==null)throw new IllegalStateException("Missing original instruction at "+Long.toHexString(pc));Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}
        }
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("cases",count);meta.put("instruction_steps",totalSteps);meta.put("mode_callbacks",modeCallbacks);meta.put("distinct_executed_instructions",visited.size());meta.put("all_expected_results_match",true);meta.put("stub_calls",stubCounts);meta.put("entry","0040a718");meta.put("stop","0040a85a before final POP PC");
        meta.put("scope","48 original-worker fixtures: both ports, destination word 5499/5500/5501, mode getter 0/1, status bit0 active/inactive, and scripted command0x83 success/failure. In inactive fixtures the 0x83 result profile is unused. Measured voltage differs from destination and deliberately crosses the threshold independently. Asserts high-power callback arguments, measured telemetry, status, protocol-cache callback, ordering, 18-byte raw cache and surrounding context/guards. Scripted 0x82 helper writes exactly 16 data bytes plus a synthesized checksum; copied byte17 retains controlled stack poison. Stops before final POP PC. No physical bus or charger accessed.");
        meta.put("excluded_calls",new String[]{"0040a5f4 reconcile","00414c80 command0x82 helper including physical bus/checksum verification","00403154 memcpy replaced by exact bytecopy","00417d60 mode getter","00408ecc high-power reconciliation","00409dd8 high-power setter body and downstream PFC/allocation","00417ba4 UI mode getter","00414dac command0x83 helper including physical bus/checksum verification","00409c1c protocol state transition body","00414c70 sensor lookup body","0040a57c aggregate updater body","00405d88 telemetry accumulator body","00405e5c protocol-cache updater body"});
        meta.put("unexercised_paths",new String[]{"0x82 failure","factory-display status bit9","revision metadata write","recovery status mask0x84/config bit1","protocol-zero/nonzero debounce threshold transitions","memcmp stable-protocol path","real controller responses, units/calibration, timers, PFC, actual negotiation"});
        meta.put("emulator_workaround","Instance-local fixed-Thumb setISAMode callback replacement; rejects ARM transitions and retains original instruction p-code/firmware bytes. External calls execute the original BL then return to actual LR via scripted entry stubs.");
        Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);
        println("CUKTECH HUSB status verification: "+count+" cases / "+totalSteps+" original instructions");
    }
}
