package org.itxtech.nemisys.synapse.network;

import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.network.SourceInterface;
import org.itxtech.nemisys.network.protocol.mcpe.DataPacket;
import org.itxtech.nemisys.network.protocol.spp.RedirectPacket;

/**
 * Created by boybook on 16/6/24.
 */
public class SynLibInterface implements SourceInterface {

    private final SynapseInterface synapseInterface;

    public SynLibInterface(SynapseInterface synapseInterface) {
        this.synapseInterface = synapseInterface;
    }

    @Override
    public void emergencyShutdown() {
    }

    @Override
    public void setName(String name) {

    }

    @Override
    public int getNetworkLatency(Player player) {
        return player.latency;
    }

    @Override
    public Integer putPacket(Player player, DataPacket packet) {
        return this.putPacket(player, packet, false);
    }

    @Override
    public Integer putPacket(Player player, DataPacket packet, boolean needACK) {
        return this.putPacket(player, packet, needACK, false);
    }

    @Override
    public Integer putPacket(Player player, DataPacket packet, boolean needACK, boolean immediate) {
        if (!player.closed) {
            packet.encode();
            RedirectPacket pk = new RedirectPacket();
            pk.compressionAlgorithm = player.getCompressor().getAlgorithm();
            pk.protocol = player.getProtocol();
            pk.sessionId = player.getSessionId();
//            pk.direct = immediate;
            pk.mcpeBuffer = packet.getBuffer();
            this.synapseInterface.putPacket(pk);
        }
        return 0;  //这个返回值在nk中并没有被用到
    }

    @Override
    public boolean process() {
        return false;
    }

    @Override
    public void close(Player player, String reason) {

    }

    @Override
    public void close(Player player) {

    }

    @Override
    public void shutdown() {

    }
}
