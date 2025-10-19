package org.itxtech.nemisys.network.protocol.mcpe;

import org.itxtech.nemisys.network.CompressionAlgorithm;
import org.itxtech.nemisys.network.Compressor;
import org.itxtech.nemisys.utils.BinaryStream;

import javax.annotation.Nullable;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public abstract class DataPacket extends BinaryStream implements Cloneable {

    public volatile boolean isEncoded = false;
    private int channel = 0;
    public byte compressor = CompressionAlgorithm.ZLIB;

    public abstract int pid();

    public boolean canBeSentBeforeLogin() {
        return false;
    }

    public void decode() {
    }

    public void encode() {
    }

    public void tryEncode() {
        if (!this.isEncoded) {
            this.isEncoded = true;
            this.encode();
        }
    }

    public void encode(int protocol, boolean netease) {
        this.encode();
    }

    public void decode(int protocol, boolean netease) {
        this.decode();
    }

    public void tryEncode(int protocol, boolean netease) {
        this.tryEncode();
    }

    @Override
    public void reset() {
        reset(ProtocolInfo.MINIMUM_PROTOCOL);
    }

    public void reset(int protocol) {
        super.reset();

        if (protocol >= 282) {
            this.putUnsignedVarInt(this.pid());
        } else if (protocol > 113) {
            this.putUnsignedVarInt(this.pid());
            this.putByte((byte) 0);
        } else {
            this.putByte((byte) this.pid());
        }
    }

    public int getChannel() {
        return channel;
    }

    public void setChannel(int channel) {
        this.channel = channel;
    }

    public DataPacket clean() {
        this.setBuffer(null);

        this.isEncoded = false;
        this.offset = 0;
        return this;
    }

    @Override
    public DataPacket clone() {
        try {
            return (DataPacket) super.clone();
        } catch (CloneNotSupportedException e) {
            return null;
        }
    }

    @Nullable
    public final Compressor getCompressor() {
        return Compressor.get(compressor);
    }
}
