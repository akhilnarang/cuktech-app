// Original HUSB switch initializer, through argument preparation for its named log.
// Stops before the logger, controller bus, ROM or hardware. Arg: new output directory.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.*;
import com.google.gson.Gson;

/**
 * Checks the original HUSB switch initializer up to the argument setup for its named log. It
 * covers both ports, all initial bytes and all 16 enable combinations. It stops before the logger.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-protocol-switches}</li>
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
public class VerifyProtocolSwitches extends GhidraScript {
    private long steps;
    private final TreeSet<Long> visited=new TreeSet<>();
    private long read(EmulatorHelper emu,long address,int size) {byte[] b=emu.readMemory(toAddr(address),size);long value=0;for(int n=0;n<size;n++)value|=(long)Byte.toUnsignedInt(b[n])<<(8*n);return value;}
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        Path out=Paths.get(getScriptArgs()[0]);if(Files.exists(out))throw new IllegalArgumentException("Output must be new");Files.createDirectories(out);Gson json=new Gson();int count=0;
        long context=0x2000cf28L,stack=0x2007c000L;
        try(var w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)) {
            for(int port=0;port<2;port++)for(int original=0;original<256;original++)for(int enabled=0;enabled<16;enabled++) {
                int mi=enabled&1,ufcs=(enabled>>1)&1,pd=(enabled>>2)&1,pps=(enabled>>3)&1;
                int expected=(original&0xe2)|(mi==0?1:0)|(ufcs==0?4:0)|(pd==0?8:0)|(pps==0?16:0);
                EmulatorHelper emu=new EmulatorHelper(currentProgram);long used=0;
                try {
                    for(int n=0;n<13;n++)emu.writeRegister("r"+n,0);
                    for(String flag:new String[]{"CY","OV","NG","ZR"})emu.writeRegister(flag,0);
                    byte[] before=new byte[0x40];Arrays.fill(before,(byte)0x5a);before[port*5+0x13]=(byte)original;
                    emu.writeMemory(toAddr(context),before);emu.writeRegister("sp",stack);emu.writeMemoryValue(toAddr(stack+32),4,pps);
                    emu.writeRegister("r0",port);emu.writeRegister("r1",mi);emu.writeRegister("r2",ufcs);emu.writeRegister("r3",pd);
                    emu.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);
                    // The skipped PUSH saves eight registers; reproduce only that
                    // stack layout. Its fifth argument is at SP+32 in this block.
                    emu.writeRegister(emu.getPCRegister(),0x409e86L);
                    while(emu.getExecutionAddress().getOffset()!=0x409eceL) {
                        monitor.checkCancelled();long pc=emu.getExecutionAddress().getOffset();
                        if(pc<0x409e86L||pc>=0x409eceL||++used>100)throw new IllegalStateException("Escaped initializer");
                        visited.add(pc);if(!emu.step(monitor))throw new IllegalStateException(emu.getLastError());
                    }
                    byte[] after=emu.readMemory(toAddr(context),before.length);int actual=Byte.toUnsignedInt(after[port*5+0x13]);
                    before[port*5+0x13]=(byte)expected;if(!Arrays.equals(before,after))throw new IllegalStateException("Initializer changed wrong field/bit");
                    if(emu.readRegister("r0").longValue()!=0x475117L||emu.readRegister("r1").intValue()!=port||emu.readRegister("r2").intValue()!=mi||emu.readRegister("r3").intValue()!=ufcs||read(emu,stack,4)!=pps||read(emu,stack+4,4)!=pd)throw new IllegalStateException("Named log argument order mismatch");
                    steps+=used;Map<String,Object> row=new LinkedHashMap<>();row.put("port",port);row.put("original_disable_byte",original);row.put("enable_bits_mi_ufcs_pd_pps",enabled);row.put("actual_disable_byte",actual);row.put("expected_disable_byte",expected);row.put("log_args_port_mipps_ufcs_pps_pd",new int[]{port,mi,ufcs,pps,pd});row.put("other_context_bytes_preserved",true);row.put("instruction_steps",used);w.write(json.toJson(row));w.newLine();count++;
                }finally{emu.dispose();}
            }
        }
        try(var w=Files.newBufferedWriter(out.resolve("executed-instructions.jsonl"),StandardCharsets.UTF_8)) {
            for(long pc:visited) {var ins=getInstructionAt(toAddr(pc));if(ins==null)throw new IllegalStateException("Missing original instruction");Map<String,Object> row=new LinkedHashMap<>();row.put("address",String.format("%08x",pc));row.put("instruction",ins.toString());row.put("bytes",HexFormat.of().formatHex(ins.getBytes()));w.write(json.toJson(row));w.newLine();}
        }
        Map<String,Object> result=new LinkedHashMap<>();result.put("sha256",sha);result.put("cases",count);result.put("instruction_steps",steps);result.put("all_expected_results_match",true);result.put("entry","00409e86");result.put("stop","00409ece before logger BL");result.put("log_format",getDataAt(toAddr(0x475117L))==null?"Original C string retained in original_bytes below":getDataAt(toAddr(0x475117L)).toString());
        result.put("original_bytes",HexFormat.of().formatHex(getBytes(toAddr(0x409e84L),0x5c)));result.put("scope","Pure HUSB disable-byte initializer and AAPCS logger argument setup: both ports, all original bytes, all16 enable combinations; reserved bits and other context bytes preserved. Prologue stack layout synthetic. No logger, bus, ROM or negotiation execution; this confirms configuration names, not active protocol enum9.");
        Files.writeString(out.resolve("verification.json"),json.toJson(result),StandardCharsets.UTF_8);println("CUKTECH protocol switch verification: "+count+" cases / "+steps+" original instructions");
    }
}
