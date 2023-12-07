package org.itxtech.nemisys.network.protocol.mcpe;

import com.nukkitx.network.raknet.RakNetReliability;
import org.itxtech.nemisys.utils.BinaryStream;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public abstract class DataPacket extends BinaryStream implements Cloneable {

    public volatile boolean isEncoded = false;
    public RakNetReliability reliability = RakNetReliability.RELIABLE_ORDERED;
    private int channel = 0;

    public abstract int pid();

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

    public void encode(int protocol) {
        this.encode();
    }

    public void decode(int protocol) {
        this.decode();
    }

    public void tryEncode(int protocol) {
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
}
