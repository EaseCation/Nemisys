package org.itxtech.nemisys.event.server;

import org.itxtech.nemisys.event.AsyncEvent;
import org.itxtech.nemisys.event.HandlerList;

import java.net.InetSocketAddress;

public class RakNetDisconnectEvent extends ServerEvent implements AsyncEvent {
    private static final HandlerList handlers = new HandlerList();

    public static HandlerList getHandlers() {
        return handlers;
    }

    private final InetSocketAddress address;

    public RakNetDisconnectEvent(InetSocketAddress address) {
        this.address = address;
    }

    public InetSocketAddress getAddress() {
        return address;
    }
}
