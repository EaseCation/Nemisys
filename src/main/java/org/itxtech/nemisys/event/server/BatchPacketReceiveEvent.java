package org.itxtech.nemisys.event.server;

import org.itxtech.nemisys.event.AsyncEvent;
import org.itxtech.nemisys.event.HandlerList;

import java.net.InetSocketAddress;

public class BatchPacketReceiveEvent extends ServerEvent implements AsyncEvent {
    private static final HandlerList handlers = new HandlerList();

    public static HandlerList getHandlers() {
        return handlers;
    }

    private final byte[] data;
    private final InetSocketAddress address;
    private final long time;

    public BatchPacketReceiveEvent(byte[] data, InetSocketAddress address, long time) {
        this.data = data;
        this.address = address;
        this.time = time;
    }

    public byte[] getData() {
        return data;
    }

    public InetSocketAddress getAddress() {
        return address;
    }

    public long getTime() {
        return time;
    }
}
