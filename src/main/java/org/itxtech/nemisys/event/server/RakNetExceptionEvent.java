package org.itxtech.nemisys.event.server;

import org.itxtech.nemisys.event.AsyncEvent;
import org.itxtech.nemisys.event.HandlerList;

import java.net.InetSocketAddress;

public class RakNetExceptionEvent extends ServerEvent implements AsyncEvent {
    private static final HandlerList handlers = new HandlerList();

    public static HandlerList getHandlers() {
        return handlers;
    }

    private final InetSocketAddress address;
    private final String reason;

    public RakNetExceptionEvent(InetSocketAddress address, String reason) {
        this.address = address;
        this.reason = reason;
    }

    public InetSocketAddress getAddress() {
        return address;
    }

    public String getReason() {
        return reason;
    }
}
