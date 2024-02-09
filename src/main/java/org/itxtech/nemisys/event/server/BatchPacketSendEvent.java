package org.itxtech.nemisys.event.server;

import org.itxtech.nemisys.event.HandlerList;

import java.net.InetSocketAddress;

public class BatchPacketSendEvent extends ServerEvent {
    private static final HandlerList handlers = new HandlerList();

    public static HandlerList getHandlers() {
        return handlers;
    }

    private final byte compressionAlgorithm;
    private final byte[] data;
    private final InetSocketAddress address;
    private final long time;

    public BatchPacketSendEvent(byte compressionAlgorithm, byte[] data, InetSocketAddress address, long time) {
        this.compressionAlgorithm = compressionAlgorithm;
        this.data = data;
        this.address = address;
        this.time = time;
    }

    public byte getCompressionAlgorithm() {
        return compressionAlgorithm;
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
