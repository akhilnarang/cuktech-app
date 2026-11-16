// Pure offline instruction emulation of the original 0073 brand classifier.
// No ADC, BLE, I2C, peripheral or ROM code is executed.
// Arg: a new absolute output directory. Run against a read-only project copy.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.Gson;

/**
 * Checks the original brand classifier with synthetic C1/C2 protocol records, OPPO, vivo and zero
 * VID values, and all 256 protocol-byte values. No ADC, BLE or I2C code runs.
 *
 * It runs original instructions in the Ghidra emulator with synthetic SRAM.
 * It does not connect to a charger and does not run peripheral, bus or ROM code.
 *
 * Arguments:
 * <ol>
 * <li>output directory: new absolute path. Example: {@code artifacts/firmware/reproduced-0073/verify-brand-classifier}</li>
 * </ol>
 *
 * Output, in the output directory:
 * <ul>
 * <li>{@code cases.jsonl}: one row for each synthetic case, with inputs and observed results.</li>
 * <li>{@code verification.json}: image hash, counts, stops and the scope of the check.</li>
 * </ul>
 *
 * Program changes: none. All writes go to the emulator state only.
 * Run it on a read-only project copy.
 *
 * It stops with an exception if the program SHA-256 is not the measured AD1204 0073 raw image
 * 65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1. It stops with an exception if the output directory already exists. It stops with an exception if an observed result differs from the expected result.
 */
public class VerifyBrandClassifier extends GhidraScript {
    private long instructionSteps;
    private int classify(int port,int vid,int protocol,long stop) throws Exception {
        EmulatorHelper emu=new EmulatorHelper(currentProgram);
        try {
            byte[] record={(byte)protocol,(byte)0x55,(byte)vid,(byte)(vid>>8),6,0};
            emu.writeMemory(toAddr(0x2000c998L+port*6),record);
            emu.writeRegister("r0",port);emu.writeRegister("r1",0);emu.writeRegister("r2",0);
            emu.writeRegister("lr",0x40306bL);
            emu.setContextRegister(currentProgram.getRegister("TMode"),BigInteger.ONE);
            emu.writeRegister(emu.getPCRegister(),0x406364L);
            int steps=0;
            while(!emu.getExecutionAddress().equals(toAddr(stop))) {
                monitor.checkCancelled();long pc=emu.getExecutionAddress().getOffset();
                if(pc<0x406364L||pc>0x4063fcL)throw new IllegalStateException("Escaped classifier: "+Long.toHexString(pc));
                if(++steps>100)throw new IllegalStateException("Classifier budget exceeded");
                if(!emu.step(monitor))throw new IllegalStateException("Emulator: "+emu.getLastError());
            }
            instructionSteps+=steps;
            return emu.readRegister("r0").intValue();
        }finally{emu.dispose();}
    }
    public void run() throws Exception {
        String sha="65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1";
        if(!sha.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong raw image");
        Path out=Paths.get(getScriptArgs()[0]);
        if(Files.exists(out))throw new IllegalArgumentException("Output directory must be new");
        Files.createDirectories(out);Gson json=new Gson();
        int[][] targets={{0x22d9,4,0x4063d4},{0x183d,5,0x4063c8},{0,0,0x4063f8}};
        ArrayList<Map<String,Object>> summaries=new ArrayList<>();int total=0;
        try(java.io.BufferedWriter w=Files.newBufferedWriter(out.resolve("cases.jsonl"),StandardCharsets.UTF_8)) {
            for(int[] target:targets)for(int port=0;port<2;port++) {
                TreeSet<Integer> observed=new TreeSet<>();
                for(int protocol=0;protocol<256;protocol++) {
                    int expected=target[0]==0?(protocol==9?1:0):target[1];
                    int actual=classify(port,target[0],protocol,target[2]);
                    Map<String,Object> row=new LinkedHashMap<>();row.put("port",port);
                    row.put("vid",target[0]);row.put("protocol",protocol);row.put("expected",expected);
                    row.put("observed",actual);w.write(json.toJson(row));w.newLine();
                    if(actual!=expected)throw new IllegalStateException("Classifier mismatch: "+json.toJson(row));
                    observed.add(actual);total++;
                }
                Map<String,Object> summary=new LinkedHashMap<>();summary.put("port",port);
                summary.put("vid",target[0]);summary.put("protocol_values",256);summary.put("returned_classes",observed);
                summaries.add(summary);
            }
        }
        Map<String,Object> result=new LinkedHashMap<>();result.put("sha256",sha);
        byte[] originalWindow=getBytes(toAddr(0x406364L),0xa0);
        result.put("classifier_window_address","00406364");
        result.put("classifier_window_hex",HexFormat.of().formatHex(originalWindow));
        result.put("classifier_window_sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(originalWindow)));
        result.put("entry","00406364");result.put("cases",total);result.put("instruction_steps",instructionSteps);
        result.put("all_expected_results_match",true);result.put("groups",summaries);
        result.put("stop_boundary","Before each fixture's expected BX LR, after result computation; return is not emulated");
        result.put("scope","Synthetic C1/C2 protocol records, OPPO/vivo/zero VID, all 256 protocol-byte values. Proves classifier independence for these inputs; does not negotiate or prove protocol support. No hardware or ROM execution.");
        Files.writeString(out.resolve("verification.json"),json.toJson(result),StandardCharsets.UTF_8);
        println("CUKTECH original classifier verified: "+total+" cases; "+instructionSteps+" instructions");
    }
}
