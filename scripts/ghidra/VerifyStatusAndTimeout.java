// Pure original-code checks: timeout LUT, SC protection mapping, periodic MIOT packer.
// Arg: new absolute output directory. Synthetic SRAM only; use -readOnly.
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
 * Checks three pure original code blocks: the timeout lookup table, the SC protection mapping and
 * the periodic MIOT packer.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-status-timeout}</li>
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
public class VerifyStatusAndTimeout extends GhidraScript {
    private long totalSteps,modeCallbacks;
    private final TreeSet<Long> visited=new TreeSet<>();
    @SuppressWarnings("unchecked")
    private EmulatorHelper fixture() throws Exception {
        EmulatorHelper helper=new EmulatorHelper(currentProgram);
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
                long pc=emulate.getExecuteAddress().getOffset();if((pc&1)!=0)emulate.setExecuteAddress(toAddr(pc&~1L));modeCallbacks++;
            });replaced=true;
        }
        if(!replaced)throw new IllegalStateException("Expected ARM handler not found");
        for(int n=0;n<13;n++)helper.writeRegister("r"+n,0);
        for(String flag:new String[]{"CY","OV","NG","ZR"})helper.writeRegister(flag,0);
        helper.writeRegister("sp",0x2007c000L);helper.writeRegister("lr",0x40306bL);
        helper.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);return helper;
    }
    private long execute(EmulatorHelper emu,long entry,long stop,long[][] allowed) throws Exception {
        emu.writeRegister(emu.getPCRegister(),entry);long steps=0;
        while(emu.getExecutionAddress().getOffset()!=stop) {
            monitor.checkCancelled();long pc=emu.getExecutionAddress().getOffset();boolean admitted=false;
            for(long[] r:allowed)if(r[0]<=pc&&pc<=r[1])admitted=true;
            if(!admitted||++steps>10000)throw new IllegalStateException("Escaped pure fixture at "+Long.toHexString(pc));
            visited.add(pc);if(!emu.step(monitor))throw new IllegalStateException(emu.getLastError());
        }
        totalSteps+=steps;return steps;
    }
    private int mapping(int mask) {return ((mask&1)!=0?0x80:0)|((mask&2)!=0?0x40:0)|((mask&4)!=0?0x20:0)|((mask&8)!=0?4:0);}
    private long read(EmulatorHelper emu,long address,int size) {byte[] bytes=emu.readMemory(toAddr(address),size);long value=0;for(int n=0;n<size;n++)value|=(long)Byte.toUnsignedInt(bytes[n])<<(8*n);return value;}
    private void write(EmulatorHelper emu,long address,int size,long value) {emu.writeMemoryValue(toAddr(address),size,value);}
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");
        Files.createDirectories(out);Gson json=new Gson();int cases=0;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)) {
            int[] seconds={300,600,1800,0,60};
            for(int value=0;value<256;value++) {
                EmulatorHelper emu=fixture();try {
                    emu.writeRegister("r0",value);long steps=execute(emu,0x40476cL,0x40477cL,new long[][]{{0x40476cL,0x40477bL}});
                    long actual=emu.readRegister("r0").longValue();int expected=value>=1&&value<=5?seconds[value-1]:0;
                    if(actual!=expected)throw new IllegalStateException("Timeout mismatch");
                    Map<String,Object> row=new LinkedHashMap<>();row.put("kind","timeout");row.put("wire_value",value);row.put("seconds",actual);row.put("expected_seconds",expected);row.put("instruction_steps",steps);w.write(json.toJson(row));w.newLine();cases++;
                }finally{emu.dispose();}
            }
            for(int index=0;index<512;index++) {
                int c3=index<256?index:(index-256)>>4,a=index<256?255-index:(index-256)&15;
                EmulatorHelper emu=fixture();try {
                    long context=0x20010000L,records=0x20010100L;byte[] guard=new byte[16];Arrays.fill(guard,(byte)0xa5);
                    emu.writeMemory(toAddr(context),new byte[0x80]);emu.writeMemory(toAddr(records),new byte[0x20]);
                    emu.writeMemory(toAddr(records-16),guard);emu.writeMemory(toAddr(records+0x20),guard);
                    write(emu,context,1,0x90);write(emu,context+0x32,1,c3);write(emu,context+0x33,1,a);
                    write(emu,records+10,2,0x101);write(emu,records+4,2,0x801);
                    emu.writeRegister("r7",context);emu.writeRegister("r4",records);
                    long steps=execute(emu,0x4154fcL,0x415580L,new long[][]{{0x4154fcL,0x41557fL},{0x405534L,0x40553fL},{0x4055ceL,0x4055d9L}});
                    long c3status=read(emu,records+10,2),astatus=read(emu,records+4,2),global=read(emu,context,1);
                    if(c3status!=(0x101|mapping(c3))||astatus!=(0x801|mapping(a))||global!=(0x90|((c3&15)!=0?4:0)|((a&15)!=0?0x40:0)))throw new IllegalStateException("Protection mapping mismatch");
                    if(!Arrays.equals(guard,emu.readMemory(toAddr(records-16),16))||!Arrays.equals(guard,emu.readMemory(toAddr(records+0x20),16)))throw new IllegalStateException("Guard mismatch");
                    Map<String,Object> row=new LinkedHashMap<>();row.put("kind","sc_mapping");row.put("c3_mask",c3);row.put("a_mask",a);row.put("c3_status",c3status);row.put("a_status",astatus);row.put("aggregate",global);row.put("guards_intact",true);row.put("instruction_steps",steps);w.write(json.toJson(row));w.newLine();cases++;
                }finally{emu.dispose();}
            }
            for(int pd=0;pd<2;pd++)for(int status=0;status<256;status++) {
                EmulatorHelper emu=fixture();try {
                    emu.writeMemory(toAddr(0x2000c9b8L),new byte[0x90]);emu.writeMemory(toAddr(0x2000c998L),new byte[0x20]);
                    emu.writeMemory(toAddr(0x2000eb80L),new byte[0x80]);emu.writeMemory(toAddr(0x2000ec18L),new byte[40]);write(emu,0x2000c8beL,2,0);
                    write(emu,0x2000c9bbL,1,1);int[] volts={9000,8500,5000,5000,12000},amps={1500,1700,1000,500,2000},caps={4,7,0x60,0x60,0xb};
                    for(int port=0;port<5;port++) {long rec=0x2000ec18L+port*8;write(emu,rec,2,volts[port]);write(emu,rec+2,2,amps[port]);write(emu,rec+4,2,port==4?pd:status);write(emu,rec+6,1,255-status);write(emu,rec+7,1,caps[port]);}
                    long steps=execute(emu,0x4043acL,0x40463eL,new long[][]{{0x4043acL,0x40463dL},{0x4046f8L,0x404765L}});
                    long c1=read(emu,0x2000eb80L,4),c3=read(emu,0x2000eb88L,4);
                    long expectedC1=(90L<<24)|(15L<<16)|(4L<<8)|status;
                    long expectedC3=pd==1?(120L<<24)|(20L<<16)|(0x60L<<8)|0x11:(50L<<24)|(10L<<16)|(0x60L<<8)|status;
                    if(c1!=expectedC1||c3!=expectedC3)throw new IllegalStateException("Periodic MIOT packer mismatch "+status+"/"+pd+" got "+Long.toHexString(c1)+"/"+Long.toHexString(c3));
                    Map<String,Object> row=new LinkedHashMap<>();row.put("kind","periodic_packer");row.put("native_status",status);row.put("alternate_c3_active",pd);row.put("candidate_byte",255-status);row.put("c1_word",c1);row.put("c3_word",c3);row.put("instruction_steps",steps);w.write(json.toJson(row));w.newLine();cases++;
                }finally{emu.dispose();}
            }
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long pc:visited) {var ins=getInstructionAt(toAddr(pc));if(ins==null)throw new IllegalStateException("Missing instruction");Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}
        }
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",sha);meta.put("cases",cases);meta.put("timeout_cases",256);meta.put("sc_mapping_cases",512);meta.put("periodic_packer_cases",512);meta.put("instruction_steps",totalSteps);meta.put("mode_callbacks",modeCallbacks);meta.put("all_expected_results_match",true);
        meta.put("scope","Pure timeout lookup for all uint8 inputs; isolated SC status mapping over all mask values plus every low-nibble pair; periodic MIOT packing with every native status byte and alternate C3 inactive/active. Synthetic SRAM only. SC reconfiguration/disabled overwrite, UI rendering/timers, boot packer, ROM, peripherals and actual faults excluded.");
        meta.put("emulator_workaround","Instance-local fixed-Thumb setISAMode callback replacement; rejects ARM transitions and preserves original instruction p-code. Stops before original return or at end of isolated mapping block.");
        Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH status/timeout verified: "+cases+" cases / "+totalSteps+" instructions");
    }
}
