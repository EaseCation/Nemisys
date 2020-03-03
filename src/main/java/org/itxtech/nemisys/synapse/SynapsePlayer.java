package org.itxtech.nemisys.synapse;

import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.event.server.DataPacketSendEvent;
import org.itxtech.nemisys.event.synapse.player.SynapsePlayerConnectEvent;
import org.itxtech.nemisys.network.SourceInterface;
import org.itxtech.nemisys.network.protocol.mcpe.DataPacket;
import org.itxtech.nemisys.network.protocol.mcpe.LoginPacket;
import org.itxtech.nemisys.network.protocol.spp.PlayerLoginPacket;
import org.itxtech.nemisys.network.protocol.spp.PlayerLogoutPacket;
import org.itxtech.nemisys.network.protocol.spp.TransferPacket;
import org.itxtech.nemisys.utils.ClientData;
import org.itxtech.nemisys.utils.TextFormat;

import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.UUID;

public class SynapsePlayer extends Player {

    private SynapseEntry synapseEntry;
    private JsonObject cachedExtra;

    public SynapsePlayer(SourceInterface interfaz, SynapseEntry synapseEntry, Long clientID, InetSocketAddress socketAddress) {
        super(interfaz, clientID, socketAddress);
        this.synapseEntry = synapseEntry;
    }

    public void handleLoginPacket(PlayerLoginPacket packet) {
        this.isFirstTimeLogin = packet.isFirstTime;
        SynapsePlayerConnectEvent ev;
        this.getServer().getPluginManager().callEvent(ev = new SynapsePlayerConnectEvent(this, this.isFirstTimeLogin));
        if (!ev.isCancelled()) {
            this.cachedExtra = packet.extra;
            DataPacket pk = this.getSynapseEntry().getSynapse().getPacket(packet.cachedLoginPacket);
            //pk.decode();
            if (pk instanceof LoginPacket) {
                ((LoginPacket) pk).username = packet.extra.get("username").getAsString();
                ((LoginPacket) pk).xuid = packet.extra.get("xuid").getAsString();
                ((LoginPacket) pk).clientUUID = packet.uuid;
                this.neteaseClient = Optional.ofNullable(packet.extra.get("netease")).orElseGet(() -> new JsonPrimitive(false)).getAsBoolean();
            }

            this.handleDataPacket(pk);
        }
    }

    public SynapseEntry getSynapseEntry() {
        return synapseEntry;
    }

    public void transfer(String hash) {
        ClientData clients = this.getSynapseEntry().getClientData();
        if (clients.clientList.containsKey(hash)) {
            TransferPacket pk = new TransferPacket();
            pk.uuid = this.getUniqueId();
            pk.clientHash = hash;
            this.getSynapseEntry().sendDataPacket(pk);
        }
    }

    public void setUniqueId(UUID uuid) {
        this.uuid = uuid;
    }

    @Override
    public void sendDataPacket(DataPacket pk, boolean direct) {
        DataPacketSendEvent ev = new DataPacketSendEvent(this, pk);
        this.getServer().getPluginManager().callEvent(ev);
        if (!ev.isCancelled()) {
            super.sendDataPacket(pk, direct);
        }
    }

    @Override
    public void completeLoginSequence(String clientHash) {
        if (clientHash == null || clientHash.equals("")) {
            this.close("Synapse Server: " + TextFormat.RED + "No target server!");
            return;
        }
        if (!getServer().getClients().containsKey(clientHash)) {
            this.close("Synapse Server: " + TextFormat.RED + "Target server is not online!");
            return;
        }
        this.transfer(getServer().getClients().get(clientHash), cachedExtra, true);
    }

    @Override
    public void close(String reason, boolean notify) {
        super.close(reason, notify);
        if (this.synapseEntry != null) {
            PlayerLogoutPacket playerLogoutPacket = new PlayerLogoutPacket();
            playerLogoutPacket.uuid = this.getUUID();
            playerLogoutPacket.reason = reason;
            this.synapseEntry.sendDataPacket(playerLogoutPacket);
        }
    }
}
