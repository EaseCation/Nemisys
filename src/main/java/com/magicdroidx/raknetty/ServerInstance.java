package com.magicdroidx.raknetty;

import com.magicdroidx.raknetty.protocol.raknet.session.GameWrapperPacket;

import java.net.InetSocketAddress;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public interface ServerInstance {

    void openSession(InetSocketAddress address, long clientID);

    void closeSession(InetSocketAddress address, String reason);

    void handleGameWrapper(InetSocketAddress address, GameWrapperPacket packet);

    void handleRaw(String address, int port, byte[] payload);

    void notifyACK(InetSocketAddress address, int identifierACK);

}
