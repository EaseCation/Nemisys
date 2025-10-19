package org.itxtech.nemisys.network.protocol.mcpe;

import lombok.ToString;

@ToString
public class ServerToClientHandshakePacket extends DataPacket {

    public static final int NETWORK_ID = ProtocolInfo.SERVER_TO_CLIENT_HANDSHAKE_PACKET;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    public String jwt;

    @Override
    public void encode(int protocol, boolean netease) {
        this.reset(protocol);
        this.putString(this.jwt);
    }

    @Override
    public void tryEncode(int protocol, boolean netease) {
        if (!this.isEncoded) {
            this.isEncoded = true;
            this.encode(protocol, netease);
        }
    }
}
