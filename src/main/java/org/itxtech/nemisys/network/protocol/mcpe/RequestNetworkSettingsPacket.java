package org.itxtech.nemisys.network.protocol.mcpe;

import lombok.ToString;

/**
 * @since 1.19.30
 */
@ToString
public class RequestNetworkSettingsPacket extends DataPacket {
    public static final int NETWORK_ID = ProtocolInfo.REQUEST_NETWORK_SETTINGS_PACKET;

    public int protocol;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    @Override
    public boolean canBeSentBeforeLogin() {
        return true;
    }

    @Override
    public void decode() {
        this.protocol = this.getInt();
    }
}
