package org.itxtech.nemisys.network.protocol.mcpe;

import lombok.ToString;

/**
 * @since 1.16.0
 */
@ToString
public class PacketViolationWarningPacket extends DataPacket {
    public static final int NETWORK_ID = ProtocolInfo.PACKET_VIOLATION_WARNING_PACKET;

    public static final int TYPE_UNKNOWN = -1;
    public static final int TYPE_MALFORMED_PACKET = 0;

    public static final int SEVERITY_UNKNOWN = -1;
    public static final int SEVERITY_WARNING = 0;
    public static final int SEVERITY_FINAL_WARNING = 1;
    public static final int SEVERITY_TERMINATING_CONNECTION = 2;

    public int type = TYPE_UNKNOWN;
    public int severity = SEVERITY_UNKNOWN;
    public int packetId;
    public String context = "";

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    @Override
    public void decode() {
        type = getVarInt();
        severity = getVarInt();
        packetId = getVarInt();
        context = getString();
    }
}
