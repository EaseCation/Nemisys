package org.itxtech.nemisys.synapse.network;

import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.network.NetworkSession;
import org.itxtech.nemisys.network.protocol.mcpe.DataPacket;
import org.itxtech.nemisys.network.protocol.mcpe.NetworkSettingsPacket;
import org.itxtech.nemisys.synapse.SynapsePlayer;

public class SynapseNetworkSession implements NetworkSession {
    private final SynLibInterface synLibInterface;
    private SynapsePlayer player;

    public SynapseNetworkSession(SynLibInterface synLibInterface) {
        this.synLibInterface = synLibInterface;
    }

    public void setPlayer(SynapsePlayer player) {
        this.player = player;
    }

    @Override
    public void sendPacket(int protocol, DataPacket packet) {
        synLibInterface.putPacket(player, packet, false, true);
    }

    @Override
    public long getPing() {
        return synLibInterface.getNetworkLatency(player);
    }

    @Override
    public void close(String reason) {
        synLibInterface.close(player, reason);
    }

    @Override
    public void closeReader() {
    }

    @Override
    public void setupSettings(Player player, NetworkSettingsPacket settings) {
    }

    @Override
    public void enableEncryption(int protocol, String clientPublicKey) {
    }
}
