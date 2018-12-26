package com.magicdroidx.raknetty.handler;

import com.magicdroidx.raknetty.RakNetServer;
import com.magicdroidx.raknetty.protocol.raknet.AddressedRakNetPacket;
import com.magicdroidx.raknetty.protocol.raknet.unconnected.UnconnectedPingPacket;
import com.magicdroidx.raknetty.protocol.raknet.unconnected.UnconnectedPongPacket;
import io.netty.channel.ChannelHandlerContext;

/**
 * raknetty Project
 * Author: MagicDroidX
 */
public class UnconnectedPingHandler extends RakNetPacketHandler<UnconnectedPingPacket> {

    private RakNetServer server;
    private String serverName = "";

    public UnconnectedPingHandler(RakNetServer server) {
        super(UnconnectedPingPacket.class);
        this.server = server;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public String getServerName() {
        return serverName;
    }

    @Override
    protected void packetReceived(ChannelHandlerContext ctx, AddressedRakNetPacket<UnconnectedPingPacket> p) {
        UnconnectedPingPacket ping = p.content();

        UnconnectedPongPacket pong = new UnconnectedPongPacket();
        pong.pingId = ping.pingId;
        pong.serverGUID = server.uuid().getMostSignificantBits();
        //TODO: Customize
        pong.serverName = this.serverName;

        ctx.writeAndFlush(new AddressedRakNetPacket<>(pong, p.sender()));
    }
}
