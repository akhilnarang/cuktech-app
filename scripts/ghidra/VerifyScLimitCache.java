// Original SC2021 limit/cache and retry control flow. Synthetic SRAM only.
// External logger/delay/I2C helper entries are stubbed without patching code.
// Arg: new output directory. Run against the unchanged 0073 project, read-only.
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
 * Checks the original SC2021 limit cache, protocol cache and retry control flow. Logger, delay and
 * I2C helper entries are stubbed. The code is not patched.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-sc-limit-cache}</li>
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
public class VerifyScLimitCache extends GhidraScript {
    private static final String SHA="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
    private static final long CONTEXT=0x2000ce70L;
    private long totalSteps,modeCallbacks;
    private final TreeSet<Long> visited=new TreeSet<>();
    private final Map<String,Long> stubCounts=new TreeMap<>();
    @SuppressWarnings("unchecked")
    private EmulatorHelper fixture() throws Exception {
        EmulatorHelper emu=new EmulatorHelper(currentProgram);
        // Ghidra 12.1.4's ARM callback attempts a context write while stepping.
        // Replace only this emulator instance's callback, retaining original
        // instruction p-code and rejecting any transition out of Thumb mode.
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
        emu.writeRegister("sp",0x2007c000L);emu.writeRegister("lr",0x40306bL);
        emu.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);
        return emu;
    }
    private int reg(EmulatorHelper emu,int n) {return emu.readRegister("r"+n).intValue();}
    private void returnStub(EmulatorHelper emu,String name,int result) {
        stubCounts.merge(name,1L,Long::sum);
        long next=emu.readRegister("lr").longValue()&~1L;
        emu.writeRegister("r0",Integer.toUnsignedLong(result));
        emu.writeRegister(emu.getPCRegister(),next);
    }
    private void step(EmulatorHelper emu,long low,long high) throws Exception {
        long pc=emu.getExecutionAddress().getOffset();
        if(pc<low||pc>=high)throw new IllegalStateException("Escaped fixture at "+Long.toHexString(pc));
        visited.add(pc);if(!emu.step(monitor))throw new IllegalStateException(emu.getLastError());
        totalSteps++;
    }
    private Map<String,Object> limit(int high,int low,int previous,int profile) throws Exception {
        int desired=(high<<4)|(low&15),writeResult=profile==1?0:1;
        int readResult=profile==2?(desired^255):desired;
        EmulatorHelper emu=fixture();long start=totalSteps;int writes=0,reads=0,iterations=0;
        byte[] before=new byte[0x60];Arrays.fill(before,(byte)0x5a);before[17]=(byte)previous;
        try {
            emu.writeMemory(toAddr(CONTEXT-16),before);
            emu.writeRegister("r0",high);emu.writeRegister("r1",low);
            emu.writeRegister(emu.getPCRegister(),0x41631cL);
            while(emu.getExecutionAddress().getOffset()!=0x416374L) {
                monitor.checkCancelled();if(++iterations>200)throw new IllegalStateException("Limit fixture runaway");
                long pc=emu.getExecutionAddress().getOffset();
                if(pc==0x4239b8L) {returnStub(emu,"logger",0);continue;}
                if(pc==0x4051b0L) {returnStub(emu,"delay",0);continue;}
                if(pc==0x415b3cL) {
                    if(reg(emu,0)!=0x42||reg(emu,1)!=0x0e||reg(emu,2)!=desired)throw new IllegalStateException("Wrong limit bus arguments");
                    writes++;returnStub(emu,"limit_write_helper",writeResult);continue;
                }
                if(pc==0x40407cL) {
                    if(reg(emu,0)!=0x42||reg(emu,1)!=0x0e)throw new IllegalStateException("Wrong readback bus arguments");
                    reads++;returnStub(emu,"limit_read_helper",readResult);continue;
                }
                step(emu,0x41631cL,0x416374L);
            }
            int expectedWrites=previous==desired?0:1;
            int expectedReads=expectedWrites==1&&desired!=0?1:0;
            byte[] expected=before.clone();expected[17]=(byte)desired;
            byte[] after=emu.readMemory(toAddr(CONTEXT-16),before.length);
            if(writes!=expectedWrites||reads!=expectedReads||!Arrays.equals(after,expected))throw new IllegalStateException("Limit cache/read/write/guard mismatch");
            Map<String,Object> row=new LinkedHashMap<>();row.put("kind","limit_cache");
            row.put("high_nibble",high);row.put("low_nibble",low);row.put("previous_cached_byte",previous);row.put("desired_byte",desired);
            row.put("write_helper_result",writeResult);row.put("readback_result",readResult);row.put("profile",new String[]{"successful_matching","failed_matching","successful_mismatched"}[profile]);
            row.put("write_helper_calls",writes);row.put("read_helper_calls",reads);row.put("actual_cached_byte",Byte.toUnsignedInt(after[17]));
            row.put("expected_write_calls",expectedWrites);row.put("expected_read_calls",expectedReads);row.put("other_context_and_guards_preserved",true);row.put("instruction_steps",totalSteps-start);return row;
        }finally{emu.dispose();}
    }
    private Map<String,Object> retry(int successAttempt) throws Exception {
        EmulatorHelper emu=fixture();long start=totalSteps;int attempts=0,iterations=0;
        try {
            emu.writeRegister("r0",0x42);emu.writeRegister("r1",0x0e);emu.writeRegister("r2",0x43);
            emu.writeRegister(emu.getPCRegister(),0x415b3cL);
            while(true) {
                monitor.checkCancelled();if(++iterations>300)throw new IllegalStateException("Retry fixture runaway");
                long pc=emu.getExecutionAddress().getOffset();
                if(pc==0x415b6eL||pc==0x415b74L)break; // Stop before original POP PC.
                if(pc==0x4239b8L) {returnStub(emu,"logger",0);continue;}
                if(pc==0x4051b0L) {returnStub(emu,"delay",0);continue;}
                if(pc==0x40410cL) {
                    if(reg(emu,0)!=0x42||reg(emu,1)!=0x0e||reg(emu,2)!=0x43)throw new IllegalStateException("Retry failed to preserve bus arguments");
                    attempts++;returnStub(emu,"single_write",attempts==successAttempt?1:0);continue;
                }
                step(emu,0x415b3cL,0x415b78L);
            }
            int expectedAttempts=successAttempt==0?3:successAttempt,expectedResult=successAttempt==0?0:1;
            if(attempts!=expectedAttempts||reg(emu,0)!=expectedResult)throw new IllegalStateException("Retry attempt/result mismatch");
            Map<String,Object> row=new LinkedHashMap<>();row.put("kind","retry_helper");row.put("scripted_success_attempt",successAttempt);row.put("actual_attempts",attempts);row.put("expected_attempts",expectedAttempts);row.put("actual_result",reg(emu,0));row.put("expected_result",expectedResult);row.put("instruction_steps",totalSteps-start);return row;
        }finally{emu.dispose();}
    }
    private Map<String,Object> protocol(int port,int ufcs,int scp,int previous) throws Exception {
        int desired=(previous&0x6f)|(ufcs==0?0x80:0)|(scp==0?0x10:0);
        int index=16+0x0e+port;
        EmulatorHelper emu=fixture();long start=totalSteps;
        byte[] before=new byte[0x60];Arrays.fill(before,(byte)0x5a);before[index]=(byte)previous;
        int[] actualWrites=new int[2],actualResults=new int[2];
        try {
            emu.writeMemory(toAddr(CONTEXT-16),before);
            for(int invocation=0;invocation<2;invocation++) {
                emu.writeRegister("sp",0x2007c000L);emu.writeRegister("lr",0x40306bL);
                emu.writeRegister("r0",port);emu.writeRegister("r1",ufcs);emu.writeRegister("r2",scp);
                emu.writeRegister(emu.getPCRegister(),0x4158e8L);int iterations=0;
                while(emu.getExecutionAddress().getOffset()!=0x41595cL) {
                    monitor.checkCancelled();if(++iterations>150)throw new IllegalStateException("Protocol fixture runaway");
                    long pc=emu.getExecutionAddress().getOffset();
                    if(pc==0x4239b8L) {returnStub(emu,"logger",0);continue;}
                    if(pc==0x4051b0L) {returnStub(emu,"delay",0);continue;}
                    if(pc==0x415b3cL) {
                        if(reg(emu,0)!=0x42||reg(emu,1)!=0x0c+port||reg(emu,2)!=desired)throw new IllegalStateException("Wrong protocol bus arguments");
                        actualWrites[invocation]++;returnStub(emu,"protocol_write_helper",0);continue;
                    }
                    step(emu,0x4158e8L,0x41595cL);
                }
                actualResults[invocation]=reg(emu,0);
                byte[] expected=before.clone();expected[index]=(byte)desired;
                if(!Arrays.equals(expected,emu.readMemory(toAddr(CONTEXT-16),before.length)))throw new IllegalStateException("Protocol cache/guard mismatch");
            }
            int firstWrites=previous==desired?0:1,firstResult=firstWrites==0?1:0;
            if(actualWrites[0]!=firstWrites||actualWrites[1]!=0||actualResults[0]!=firstResult||actualResults[1]!=1)throw new IllegalStateException("Protocol failure/repeat mismatch");
            Map<String,Object> row=new LinkedHashMap<>();row.put("kind","protocol_cache_repeat");row.put("port",port);row.put("ufcs_enabled",ufcs);row.put("scp_enabled",scp);row.put("previous_cached_byte",previous);row.put("desired_byte",desired);
            row.put("scripted_write_helper_result",0);row.put("write_helper_calls_first_then_repeat",actualWrites);row.put("results_first_then_repeat",actualResults);row.put("expected_first_write_calls",firstWrites);row.put("expected_first_result",firstResult);row.put("other_context_and_guards_preserved",true);row.put("instruction_steps",totalSteps-start);return row;
        }finally{emu.dispose();}
    }
    public void run() throws Exception {
        if(!SHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        String[] args=getScriptArgs();if(args.length!=1)throw new IllegalArgumentException("Expected new output directory");
        Path out=Paths.get(args[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);
        Gson json=new Gson();int count=0,limitCases=0,protocolCases=0;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)) {
            for(int high=0;high<16;high++)for(int low=0;low<16;low++) {
                int desired=(high<<4)|low;
                Set<Integer> priors=new LinkedHashSet<>(Arrays.asList(0,1,0x21,0x43,0x80,0xff,desired));
                for(int previous:priors)for(int profile=0;profile<3;profile++) {w.write(json.toJson(limit(high,low,previous,profile)));w.newLine();count++;limitCases++;}
            }
            for(int successAttempt=0;successAttempt<4;successAttempt++) {w.write(json.toJson(retry(successAttempt)));w.newLine();count++;}
            for(int port=0;port<2;port++)for(int enabled=0;enabled<4;enabled++)for(int previous:new int[]{0,255,0x5a,0xa5}) {
                w.write(json.toJson(protocol(port,enabled&1,(enabled>>1)&1,previous)));w.newLine();count++;protocolCases++;
            }
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long pc:visited) {var ins=getInstructionAt(toAddr(pc));if(ins==null)throw new IllegalStateException("Missing original instruction at "+Long.toHexString(pc));Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}
        }
        Map<String,Object> meta=new LinkedHashMap<>();meta.put("sha256",SHA);meta.put("cases",count);meta.put("limit_cache_cases",limitCases);meta.put("retry_cases",4);meta.put("protocol_cache_cases",protocolCases);meta.put("instruction_steps",totalSteps);meta.put("mode_callbacks",modeCallbacks);meta.put("distinct_executed_instructions",visited.size());meta.put("all_expected_results_match",true);meta.put("stub_calls",stubCounts);
        meta.put("limit_entry","0041631c");meta.put("limit_stop","00416374 before POP");meta.put("retry_entry","00415b3c");meta.put("retry_stops",new String[]{"00415b6e before failure POP","00415b74 before success POP"});
        meta.put("protocol_entry","004158e8");meta.put("protocol_stop","0041595c before POP");
        meta.put("emulator_workaround","Instance-local fixed-Thumb setISAMode callback replacement matching the existing status/timeout verifier. Rejects ARM transitions; original instruction p-code and firmware bytes unchanged. Initial run without this workaround failed at the first logger BL and does not count as a completed verification.");
        meta.put("scope","Original limit pack/cache control flow across all 16x16 nibble combinations and selected prior cache bytes; synthetic successful/failed write returns and matching/mismatched readback returns. Separate original retry-loop fixtures succeed on attempt 1/2/3 or exhaust all three. Original protocol-cache fixtures cover both ports, all UFCS/SCP combinations and four prior bytes: changed requests receive a synthetic exhausted-write failure, then an identical invocation must return success without writing. Cases already matching the desired cache skip both writes. Calls execute the original BL; external logger/delay/I2C entry points are stubbed by returning to actual LR without modifying original bytes. Stops before POP PC. Synthetic SRAM only; physical bus, controller firmware, negotiation, electrical limits, protection replay and actual faults excluded. Stub return values are test inputs, not observed hardware failures.");
        Files.writeString(out.resolve("verification.json"),json.toJson(meta),StandardCharsets.UTF_8);
        println("CUKTECH SC limit/cache verification: "+count+" cases / "+totalSteps+" original instructions");
    }
}
