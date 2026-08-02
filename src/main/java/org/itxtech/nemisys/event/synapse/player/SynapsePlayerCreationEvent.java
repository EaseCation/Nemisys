package org.itxtech.nemisys.event.synapse.player;

import org.itxtech.nemisys.event.HandlerList;
import org.itxtech.nemisys.event.synapse.SynapseEvent;
import org.itxtech.nemisys.network.Compressor;
import org.itxtech.nemisys.network.NetworkSession;
import org.itxtech.nemisys.network.SourceInterface;
import org.itxtech.nemisys.synapse.SynapseEntry;
import org.itxtech.nemisys.synapse.SynapsePlayer;

import java.net.InetSocketAddress;
import java.util.Objects;

/**
 */
public class SynapsePlayerCreationEvent extends SynapseEvent {

    private static final HandlerList handlers = new HandlerList();
    private final SourceInterface interfaz;
    private final Long clientId;
    private final InetSocketAddress socketAddress;
    private SynapsePlayerFactory playerFactory;

    public SynapsePlayerCreationEvent(SourceInterface interfaz, SynapsePlayerFactory playerFactory, Long clientId, InetSocketAddress socketAddress) {
        this.interfaz = interfaz;
        this.clientId = clientId;
        this.socketAddress = socketAddress;
        this.playerFactory = playerFactory;
    }

    public static HandlerList getHandlers() {
        return handlers;
    }

    public SourceInterface getInterface() {
        return interfaz;
    }

    public String getAddress() {
        return this.socketAddress.getAddress().toString();
    }

    public int getPort() {
        return this.socketAddress.getPort();
    }

    public InetSocketAddress getSocketAddress() {
        return socketAddress;
    }

    public Long getClientId() {
        return clientId;
    }

    public SynapsePlayerFactory getPlayerFactory() {
        return playerFactory;
    }

    public void setPlayerFactory(SynapsePlayerFactory playerFactory) {
        Objects.requireNonNull(playerFactory, "constructor");
        this.playerFactory = playerFactory;
    }

    @FunctionalInterface
    public interface SynapsePlayerFactory {
        SynapsePlayer create(NetworkSession session, SynapseEntry synapseEntry, Long clientID, InetSocketAddress socketAddress, Compressor compressor);
    }
}
