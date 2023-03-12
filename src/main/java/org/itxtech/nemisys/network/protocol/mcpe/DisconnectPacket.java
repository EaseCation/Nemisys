package org.itxtech.nemisys.network.protocol.mcpe;

/**
 * Created by on 15-10-12.
 */
public class DisconnectPacket extends DataPacket {
    public static final int NETWORK_ID = ProtocolInfo.DISCONNECT_PACKET;

    public boolean hideDisconnectionScreen = false;
    public String message;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    @Override
    public void decode(int protocol) {
        this.hideDisconnectionScreen = this.getBoolean();
        this.message = this.getString();
    }

    @Override
    public void encode(int protocol) {
         this.reset(protocol);
        this.putBoolean(this.hideDisconnectionScreen);
        if (!this.hideDisconnectionScreen) {
            this.putString(this.message);
        }
    }

    @Override
    public void tryEncode(int protocol) {
        if (!this.isEncoded) {
            this.isEncoded = true;
            this.encode(protocol);
        }
    }
}
