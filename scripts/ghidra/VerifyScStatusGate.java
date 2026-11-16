// SC2021 normal-packet enum gate and protection-consumer control flow.
// Synthetic SRAM; no peripheral, CRC/read helper or full-handler execution.
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
 * Checks the original SC2021 normal-packet enum gate and the protection consumer. The helpers at
 * 0x00405534 and 0x004055ce run. Logger, delay and bus-write bodies are stubbed.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-sc-status-gate}</li>
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
public class VerifyScStatusGate extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private static final long CTX=0x2000ce70L, OUT=0x20070000L;
    private long steps,callbacks;
    private final TreeSet<Long> visited=new TreeSet<>();
    @SuppressWarnings("unchecked")
    private EmulatorHelper fixture() throws Exception {
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        var outer=e.getEmulator().getClass().getDeclaredField("emulator");outer.setAccessible(true);
        Emulate engine=(Emulate)outer.get(e.getEmulator());
        var field=Emulate.class.getDeclaredField("instructionStateModifier");field.setAccessible(true);
        var modifier=(EmulateInstructionStateModifier)field.get(engine);
        var mapping=EmulateInstructionStateModifier.class.getDeclaredField("pcodeOpMap");mapping.setAccessible(true);
        Map<Integer,OpBehaviorOther> operations=(Map<Integer,OpBehaviorOther>)mapping.get(modifier);boolean found=false;
        for(int n:new ArrayList<>(operations.keySet())) {
            if(!"setISAMode".equals(currentProgram.getLanguage().getUserDefinedOpName(n)))continue;
            operations.put(n,(emulate,output,inputs)-> {
                if(emulate.getMemoryState().getValue(currentProgram.getRegister("ISAModeSwitch"))!=1)throw new IllegalStateException("Unexpected ARM transition");
                long pc=emulate.getExecuteAddress().getOffset();if((pc&1)!=0)emulate.setExecuteAddress(toAddr(pc&~1L));callbacks++;
            });found=true;
        }
        if(!found)throw new IllegalStateException("Missing setISAMode callback");
        for(int n=0;n<13;n++)e.writeRegister("r"+n,0);
        for(String flag:new String[]{"CY","OV","NG","ZR"})e.writeRegister(flag,0);
        e.writeRegister("sp",0x2007c000L);e.writeRegister("lr",0x40306bL);
        e.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);return e;
    }
    private int r(EmulatorHelper e,int n){return e.readRegister("r"+n).intValue();}
    private void stub(EmulatorHelper e,int value){long next=e.readRegister("lr").longValue()&~1L;e.writeRegister("r0",Integer.toUnsignedLong(value));e.writeRegister(e.getPCRegister(),next);}
    private void put16(byte[] b,int at,int value){b[at]=(byte)value;b[at+1]=(byte)(value>>8);}
    private int mapped(int p){return 1|((p&1)!=0?0x80:0)|((p&2)!=0?0x40:0)|((p&4)!=0?0x20:0)|((p&8)!=0?4:0);}
    private Map<String,Object> runCase(int c3,int a,int cp,int ap,int load) throws Exception {
        EmulatorHelper e=fixture();long begin=steps;int iterations=0,writes=0;
        byte[] context=new byte[0x70];Arrays.fill(context,(byte)0x5a);
        int base=16;context[base]=0;context[base+1]=0x21;context[base+2]=(byte)0x82;context[base+3]=8;context[base+4]=0;
        context[base+8]=0x77;context[base+9]=(byte)0x88;context[base+0xe]=0x40;context[base+0xf]=0x50;
        context[base+0x20]=0x55;context[base+0x21]=0x66;context[base+0x22]=0x33;context[base+0x23]=0x44;
        byte[] packet={(byte)(1|(load<<2)),1,0x12,0x34,0x56,0x78,0x13,0x57,0x24,0x68,(byte)c3,(byte)a,(byte)cp,(byte)ap,0x39,0x12,0x76};
        System.arraycopy(packet,0,context,base+0x26,packet.length);
        byte[] output=new byte[44];Arrays.fill(output,(byte)0xa6);
        byte[] expectedContext=context.clone(),expectedOutput=output.clone();
        boolean accepted=c3<16&&a<16;
        expectedContext[base+4]=(byte)load;
        put16(expectedOutput,16,0x1357);put16(expectedOutput,18,0x2468);put16(expectedOutput,20,accepted?mapped(ap):1);
        put16(expectedOutput,22,0x1234);put16(expectedOutput,24,0x5678);put16(expectedOutput,26,accepted?mapped(cp):1);
        if(accepted) {
            expectedContext[base]=(byte)(((cp&15)!=0?4:0)|((ap&15)!=0?0x40:0));
            expectedContext[base+0x20]=(byte)(load==1?14:c3);expectedContext[base+0x21]=(byte)a;
            expectedContext[base+0x22]=(byte)cp;expectedContext[base+0x23]=(byte)ap;
            expectedContext[base+8]=(byte)a;expectedContext[base+9]=(byte)(load==1?14:c3);
        }
        int[] regs={0x20,0x0e,0x21,0x0d,0x0c},values={0x82,0x21,8,0x50,0x40};
        try {
            e.writeMemory(toAddr(CTX-16),context);e.writeMemory(toAddr(OUT-16),output);
            e.writeRegister("r1",packet[0]);e.writeRegister("r4",OUT);e.writeRegister("r7",CTX);
            e.writeRegister(e.getPCRegister(),0x4153acL);
            while(e.getExecutionAddress().getOffset()!=0x41542aL) {
                monitor.checkCancelled();if(++iterations>350)throw new IllegalStateException("Fixture runaway");
                long pc=e.getExecutionAddress().getOffset();
                if(pc==0x4239b8L||pc==0x4051b0L){stub(e,0);continue;}
                if(pc==0x415b3cL) {
                    if(writes>=5||r(e,0)!=0x42||r(e,1)!=regs[writes]||r(e,2)!=values[writes])throw new IllegalStateException("Replay bus arguments mismatch");
                    writes++;stub(e,1);continue;
                }
                boolean allowed=(pc>=0x4153acL&&pc<0x41542aL)||(pc>=0x415490L&&pc<0x4155b0L)||(pc>=0x405534L&&pc<=0x40553eL)||(pc>=0x4055ceL&&pc<=0x4055d8L);
                if(!allowed)throw new IllegalStateException("Unexpected execution at "+Long.toHexString(pc));
                visited.add(pc);if(!e.step(monitor))throw new IllegalStateException(e.getLastError());steps++;
            }
            int expectedWrites=accepted&&(cp&0x80)!=0?5:0;
            if(writes!=expectedWrites||!Arrays.equals(expectedContext,e.readMemory(toAddr(CTX-16),context.length))||!Arrays.equals(expectedOutput,e.readMemory(toAddr(OUT-16),output.length)))throw new IllegalStateException("Status gate fixture mismatch: "+c3+","+a+","+cp+","+ap+","+load);
            Map<String,Object> row=new LinkedHashMap<>();row.put("c3_protocol",c3);row.put("a_protocol",a);row.put("c3_protection",cp);row.put("a_protection",ap);row.put("pd_load",load);row.put("protocol_gate_accepted",accepted);row.put("replay_write_calls",writes);row.put("expected_replay_write_calls",expectedWrites);row.put("voltage_current_stores_match",true);row.put("protocol_protection_cache_and_status_match",true);row.put("other_context_output_and_guards_preserved",true);row.put("instruction_steps",steps-begin);return row;
        } finally {e.dispose();}
    }
    public void run() throws Exception {
        if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        String[] args=getScriptArgs();if(args.length!=1)throw new IllegalArgumentException("Expected new output directory");
        Path out=Paths.get(args[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);
        Gson json=new Gson();int count=0;int[] enums=new int[18];for(int i=0;i<16;i++)enums[i]=i;enums[16]=16;enums[17]=255;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)) {
            for(int c3:enums)for(int a:enums)for(int load=0;load<2;load++){w.write(json.toJson(runCase(c3,a,0x8f,0x8f,load)));w.newLine();count++;}
            for(int[] pair:new int[][]{{0,15},{16,15},{15,16},{255,255}})for(int port=0;port<2;port++)for(int p=0;p<256;p++)for(int load=0;load<2;load++) {
                w.write(json.toJson(runCase(pair[0],pair[1],port==0?p:0,port==1?p:0,load)));w.newLine();count++;
            }
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long pc:visited){var ins=getInstructionAt(toAddr(pc));if(ins==null)throw new IllegalStateException("Missing original instruction at "+Long.toHexString(pc));Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}
        }
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("cases",count);meta.put("instruction_steps",steps);meta.put("distinct_executed_instructions",visited.size());meta.put("mode_callbacks",callbacks);meta.put("all_expected_results_match",true);meta.put("entry","004153ac after bus/CRC accepted C3-active branch");meta.put("stop","0041542a before register-20 read/disabled-status overwrite");
        meta.put("scope","Original V/I/activity stores, protocol-byte gate, cache/protection handling and replay request selection; original 00405534/004055ce helper bodies execute. Both ports synthetic active. All pairs of protocol0..15 plus invalid16/255, both PD-load states; all256 protection bytes on each port across selected accepted/rejected pairs. Logger/delay and bus-write bodies are stubbed to return to actual LR; replay arguments checked. Bus writes always return synthetic success, with no peripheral execution. CRC acceptance is assumed at entry, not verified. Complete polling schedule, bus/register20 state, subsequent status overwrite, recovery, electrical fault meanings and physical charger effects excluded. Instance-local fixed-Thumb setISAMode workaround changes no original instructions/p-code.");
        Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);println("CUKTECH SC status gate: "+count+" cases / "+steps+" original instruction steps");
    }
}
