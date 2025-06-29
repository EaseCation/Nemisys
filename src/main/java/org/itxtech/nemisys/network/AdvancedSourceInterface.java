package org.itxtech.nemisys.network;

import io.netty.buffer.ByteBuf;

import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public interface AdvancedSourceInterface extends SourceInterface {

    void blockAddress(InetAddress address);

    void blockAddress(InetAddress address, int timeout);

    void setNetwork(Network network);

    void sendRawPacket(InetSocketAddress socketAddress, ByteBuf payload);
}
