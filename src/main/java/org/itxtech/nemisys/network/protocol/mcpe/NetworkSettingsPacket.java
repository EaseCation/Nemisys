package org.itxtech.nemisys.network.protocol.mcpe;

import lombok.ToString;
import org.itxtech.nemisys.network.CompressionAlgorithm;

@ToString
public class NetworkSettingsPacket extends DataPacket {
    public static final int NETWORK_ID = ProtocolInfo.NETWORK_SETTINGS_PACKET;

    public static final int COMPRESS_NOTHING = 0;
    public static final int COMPRESS_EVERYTHING = 1;
    public static final int COMPRESS_MAXIMUM = 65535;

    public int compressionThreshold = COMPRESS_EVERYTHING;
    public byte compressionAlgorithm = CompressionAlgorithm.ZLIB;

    public boolean enableClientThrottling;
    public byte clientThrottleThreshold;
    public int clientThrottleScalar;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    @Override
    public void encode(int protocol) {
        this.reset(protocol);
        this.putLShort(this.compressionThreshold);
        if (protocol < 554) {
            return;
        }
        this.putLShort(this.compressionAlgorithm & 0xff);
        this.putBoolean(this.enableClientThrottling);
        this.putByte(this.clientThrottleThreshold);
        this.putLFloat(this.clientThrottleScalar);
    }

    @Override
    public void tryEncode(int protocol) {
        if (this.isEncoded) {
            return;
        }
        this.isEncoded = true;
        this.encode(protocol);
    }
}
