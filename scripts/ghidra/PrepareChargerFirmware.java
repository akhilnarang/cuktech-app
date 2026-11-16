// Prepare the unmodified AD1204 2.1.2_0073 raw image for Cortex/Thumb analysis.
// Import with BinaryLoader at 0x00403000 and processor ARM:LE:32:Cortex.
// @category CUKTECH
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
import java.util.TreeSet;

/**
 * Prepares the unmodified AD1204 2.1.2_0073 raw image for Cortex/Thumb analysis. Import the image
 * with BinaryLoader at base 0x00403000 and processor ARM:LE:32:Cortex, then run this as a
 * pre-analysis script.
 * <ol>
 * <li>It renames the image block to {@code firmware_flash} (read and execute, no write).</li>
 * <li>It adds an uninitialized {@code inferred_sram} block at 0x20000000 (0x80000 bytes). This size
 * is an analysis convenience. It is not a verified memory map.</li>
 * <li>It sets TMode (Thumb) on the image.</li>
 * <li>It creates functions at known entries and at odd aligned pointers that point to a PUSH
 * prologue (0xb5xx or 0xe92d).</li>
 * <li>It adds analyst labels for known functions.</li>
 * </ol>
 *
 * Arguments: none.
 *
 * Output: the seed and function counts, in the script console.
 *
 * Program changes: memory blocks, context, functions and labels. It does not change firmware bytes.
 */
public class PrepareChargerFirmware extends GhidraScript {
    public void run() throws Exception {
        long base = 0x403000L;
        MemoryBlock image = currentProgram.getMemory().getBlock(toAddr(base));
        image.setName("firmware_flash");
        image.setRead(true); image.setWrite(false); image.setExecute(true);
        // Synthetic, uninitialized coverage for observed SRAM pointers. Its size
        // is an analysis convenience, not a verified physical memory map.
        if (currentProgram.getMemory().getBlock(toAddr(0x20000000L)) == null) {
            MemoryBlock ram = currentProgram.getMemory().createUninitializedBlock(
                "inferred_sram", toAddr(0x20000000L), 0x80000L, false);
            ram.setRead(true); ram.setWrite(true); ram.setExecute(false);
        }
        currentProgram.getProgramContext().setValue(
            currentProgram.getRegister("TMode"), image.getStart(), image.getEnd(), BigInteger.ONE);
        long[] known = {0x403040,0x403058,0x403060,0x40306a,0x403072,
            0x4048b0,0x404c10,0x404d2c,0x404dd0,0x405914,0x405a98,
            0x412898,0x4129b0,0x414618,0x41d41c};
        TreeSet<Long> seeds = new TreeSet<>();
        for (long value : known) seeds.add(value);
        // Odd in-image aligned words are possible Thumb function pointers.
        // Admit only recognizable prologues; do not treat every pointer as code.
        for (long at = base; at + 4 <= image.getEnd().getOffset(); at += 4) {
            long ptr = Integer.toUnsignedLong(getInt(toAddr(at)));
            long target = ptr & ~1L;
            if ((ptr & 1) == 0 || target < base + 0x40 || target + 4 > image.getEnd().getOffset()) continue;
            int h = Short.toUnsignedInt(getShort(toAddr(target)));
            if ((h & 0xff00) == 0xb500 || h == 0xe92d) seeds.add(target);
        }
        int created = 0;
        for (long value : seeds) {
            monitor.checkCancelled();
            Address address = toAddr(value);
            disassemble(address);
            if (getFunctionAt(address) == null && createFunction(address, null) != null) created++;
        }
        String[][] names = {
            {"00403040","image_startup"},{"00403058","image_reset_entry"},
            {"004048b0","dfu_state_transition_candidate"},
            {"00404c10","charger_set_port_enable_mask"},
            {"00404d2c","charger_set_protocol_control_u8"},
            {"00404dd0","charger_set_protocol_control_u32"},
            {"00405914","miot_property_get"},{"00405a98","miot_property_set"},
            {"00412898","dfu_event_callback"},{"004129b0","event_table_dispatch"},
            {"00414618","charger_set_shutdown_minutes"},
            {"0041d41c","miot_set_response_wrapper"}
        };
        for (String[] item : names) createLabel(toAddr(item[0]), item[1], true, SourceType.USER_DEFINED);
        println("CUKTECH seeded " + seeds.size() + " possible entries; created " + created + " functions.");
    }
}
