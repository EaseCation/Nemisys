package org.itxtech.nemisys.network.protocol.mcpe;

import lombok.ToString;

@ToString
public class ClientToServerHandshakePacket extends DataPacket {
    public static final int NETWORK_ID = ProtocolInfo.CLIENT_TO_SERVER_HANDSHAKE_PACKET;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    @Override
    public boolean canBeSentBeforeLogin() {
        return true;
    }
}
