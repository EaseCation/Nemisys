package org.itxtech.nemisys.event.player;

import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.event.Event;
import org.itxtech.nemisys.event.HandlerList;
import org.itxtech.nemisys.network.Compressor;
import org.itxtech.nemisys.network.NetworkSession;
import org.itxtech.nemisys.network.SourceInterface;

import java.net.InetSocketAddress;
import java.util.Objects;

/**
 * @author CreeperFace
 */
public class PlayerCreationEvent extends Event {

    private static final HandlerList handlers = new HandlerList();

    public static HandlerList getHandlers() {
        return handlers;
    }

    private final SourceInterface interfaz;

    private final long clientId;

    private final InetSocketAddress socketAddress;

    private PlayerFactory playerFactory;

    public PlayerCreationEvent(SourceInterface interfaz, PlayerFactory playerFactory, long clientId, InetSocketAddress socketAddress) {
        this.interfaz = interfaz;
        this.clientId = clientId;
        this.socketAddress = socketAddress;
        this.playerFactory = playerFactory;
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

    public long getClientId() {
        return clientId;
    }

    public PlayerFactory getPlayerFactory() {
        return playerFactory;
    }

    public void setPlayerFactory(PlayerFactory playerFactory) {
        Objects.requireNonNull(playerFactory, "constructor");
        this.playerFactory = playerFactory;
    }

    @FunctionalInterface
    public interface PlayerFactory {
        Player create(NetworkSession session, long clientId, InetSocketAddress socketAddress, Compressor compressor);
    }
}
