package org.itxtech.nemisys.network.protocol.mcpe;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class BatchPacket extends DataPacket {
    public static final int NETWORK_ID = ProtocolInfo.BATCH_PACKET;

    public byte[] payload;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    @Override
    public void decode() {
        this.payload = this.get();
    }

    @Override
    public void encode() {

    }
}
