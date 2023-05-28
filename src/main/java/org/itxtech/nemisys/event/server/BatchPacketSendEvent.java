package org.itxtech.nemisys.event.server;

import org.itxtech.nemisys.event.HandlerList;

import java.net.InetSocketAddress;

public class BatchPacketSendEvent extends ServerEvent {
    private static final HandlerList handlers = new HandlerList();

    public static HandlerList getHandlers() {
        return handlers;
    }

    private final byte[] data;
    private final InetSocketAddress address;
    private final long time;

    public BatchPacketSendEvent(byte[] data, InetSocketAddress address, long time) {
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
