"""Parser for Xiaomi/Mijia FE95 BLE service data frames.

Adapted from ha-cuk-ble (https://github.com/zuyan9/ha-cuk-ble, Apache License 2.0),
original at ``custom_components/cuktech_ble/lib/fe95.py`` (the two small
``util`` helpers are inlined so this copy is standalone). Additions: the
``registered``/``solicited``/``auth_mode`` frame-control properties (bit
meanings from the mijia_ble SDK ``mible_beacon_internal.h``) and the AD1204U
product-id table.
"""


from dataclasses import dataclass

# Addition: known AD1204U product ids (FE95 pid field, u16 LE).
# CN market unit: 0x660E (= 26126 decimal, model njcuk.fitting.ad1204).
# Overseas unit:  0x8AB9 (= 35513 decimal, model njcuk.fitting.1204e per the
# APK's non-cn device configs). NOTE: 0x8AD9 seen in an earlier draft is a
# transcription error. The correct value is 0x8AB9.
AD1204U_PRODUCT_IDS = frozenset({0x660E, 0x8AB9})
PID_MODEL_HINTS = {
    0x660E: "njcuk.fitting.ad1204",
    0x8AB9: "njcuk.fitting.1204e",
}


@dataclass(frozen=True)
class FE95Frame:
    """Parsed metadata from an FE95 service data frame.

    Xiaomi/Mijia FE95 frames commonly start with:

    - 2 byte frame control, little-endian
    - 2 byte product id, little-endian
    - 1 byte frame counter
    - 6 byte BLE MAC, little-endian, when present

    Attributes:
        raw: The complete service data.
        frame_control: The frame-control field (u16 LE).
        product_id: The product id (u16 LE), or ``None`` if the frame is too short.
        frame_counter: The frame counter byte, or ``None`` if the frame is too short.
        mac_address: The MAC as ``AA:BB:CC:DD:EE:FF``. ``None`` if the
            mac_include bit is clear or the frame is too short.
        payload: The bytes after the MAC field, or after the counter if
            there is no MAC.
    """

    raw: bytes
    frame_control: int
    product_id: int | None
    frame_counter: int | None
    mac_address: str | None
    payload: bytes

    @property
    def raw_hex(self) -> str:
        """The raw service data as lowercase hex."""
        return self.raw.hex()

    @property
    def frame_control_hex(self) -> str:
        """The frame-control field as ``0x`` and 4 lowercase hex digits."""
        return f"0x{self.frame_control:04x}"

    @property
    def product_id_hex(self) -> str | None:
        """The product id as ``0x`` and 4 lowercase hex digits, or ``None``."""
        if self.product_id is None:
            return None
        return f"0x{self.product_id:04x}"

    @property
    def payload_hex(self) -> str:
        """The payload as lowercase hex."""
        return self.payload.hex()

    # -------------------------------------------------- additions

    @property
    def mac_include(self) -> bool | None:
        """frame-control bit 4 (byte0 bit4): the payload carries a MAC.

        Returns:
            The bit value, or ``None`` if the frame is shorter than 2 bytes.
        """
        if len(self.raw) < 2:
            return None
        return bool(self.frame_control & 0x0010)

    @property
    def registered(self) -> bool | None:
        """frame-control bit 8 (byte1 bit0): the charger has a stored binding.

        Returns:
            The bit value, or ``None`` if the frame is shorter than 2 bytes.
        """
        if len(self.raw) < 2:
            return None
        return bool(self.frame_control & 0x0100)

    @property
    def solicited(self) -> bool | None:
        """frame-control bit 9 (byte1 bit1): the charger asks for a bind.

        Returns:
            The bit value, or ``None`` if the frame is shorter than 2 bytes.
        """
        if len(self.raw) < 2:
            return None
        return bool(self.frame_control & 0x0200)

    @property
    def auth_mode(self) -> int | None:
        """frame-control bits 10-11 (byte1 bits 2-3): auth mode.

        Returns:
            The 2-bit auth mode (0 to 3), or ``None`` if the frame is shorter
            than 2 bytes.
        """
        if len(self.raw) < 2:
            return None
        return (self.frame_control >> 10) & 0b11


def parse_fe95(service_data: bytes | bytearray | memoryview) -> FE95Frame:
    """Parse FE95 service data into stable metadata and the raw unknown payload.

    The MAC is decoded only if the mac_include bit (bit 4) is set.

    Args:
        service_data: The FE95 service data from one advertisement.

    Returns:
        The parsed frame.

    Raises:
        ValueError: If the data is shorter than 2 bytes.
    """
    data = bytes(service_data)
    if len(data) < 2:
        raise ValueError("FE95 service data must contain at least a frame control")

    frame_control = int.from_bytes(data[0:2], "little")
    product_id = int.from_bytes(data[2:4], "little") if len(data) >= 4 else None
    frame_counter = data[4] if len(data) >= 5 else None

    # The MAC field is only present when the frame-control mac_include bit
    # (bit 4) is set (mijia_ble SDK mible_beacon_internal.h). Never decode
    # positional bytes as a MAC without the flag, because the tool uploads
    # the smac as an account property.
    mac_address = None
    payload_offset = 5
    if frame_control & 0x0010 and len(data) >= 11:
        mac_address = _decode_little_endian_mac(data[5:11])
        payload_offset = 11

    return FE95Frame(
        raw=data,
        frame_control=frame_control,
        product_id=product_id,
        frame_counter=frame_counter,
        mac_address=mac_address,
        payload=data[payload_offset:],
    )


def _decode_little_endian_mac(value: bytes) -> str:
    """SMAC format: uppercase, colon-joined, reversed from little-endian.

    Pinned by the APK's PacketReader.getMac (qdj.OooO0o): ``%02X`` joined
    with colons over the reversed bytes.
    """
    if len(value) != 6:
        raise ValueError("MAC field must be exactly 6 bytes")
    return ":".join(f"{byte:02X}" for byte in reversed(value))


def smac_matches_address(frame: FE95Frame, address: str) -> bool:
    """Check that the FE95 MAC field belongs to the selected BLE address.

    Accepts either byte order of the same 6 bytes, because some firmware
    stores the address little-endian and some big-endian. The bytes must be
    the same. A different MAC is a mismatch. Never upload it as the smac
    property of the account.

    Args:
        frame: A parsed FE95 frame.
        address: The BLE address. Colons or dashes are optional.

    Returns:
        ``True`` if the MAC field matches ``address`` in either byte order.
        ``False`` if the frame has no MAC or a value is not 12 hex digits.
    """
    if frame.mac_address is None:
        return False
    smac = frame.mac_address.replace(":", "").replace("-", "").lower()
    addr = address.replace(":", "").replace("-", "").lower()
    if len(smac) != 12 or len(addr) != 12:
        return False
    smac_rev = "".join(smac[i : i + 2] for i in range(10, -1, -2))
    return smac == addr or smac_rev == addr
