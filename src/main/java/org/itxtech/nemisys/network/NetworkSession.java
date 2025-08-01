package org.itxtech.nemisys.network;

import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.network.protocol.mcpe.DataPacket;
import org.itxtech.nemisys.network.protocol.mcpe.NetworkSettingsPacket;

public interface NetworkSession {
    void sendPacket(int protocol, DataPacket packet);

    long getPing();

    void close(String reason);

    void closeReader();

    void setupSettings(Player player, NetworkSettingsPacket settings);

    void enableEncryption(int protocol, String clientPublicKey);
}
