package org.itxtech.nemisys.network.synlib;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import lombok.extern.log4j.Log4j2;
import org.itxtech.nemisys.network.protocol.spp.SynapseDataPacket;

/**
 * Handles a server-side channel.
 */
@Log4j2
public class SynapseServerHandler extends ChannelInboundHandlerAdapter {

    //static final ChannelGroup channels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
    private final SessionManager sessionManager;

    public SynapseServerHandler(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    @Override
    public void channelActive(final ChannelHandlerContext ctx) {  //客户端启动时调用该方法
        String hash = SessionManager.getChannelHash(ctx.channel());
        //Server.getInstance().getLogger().debug("server-ChannelActive: hash=" + hash);
        this.getSessionManager().getSessions().put(hash, ctx.channel());
        this.getSessionManager().getServer().addClientOpenRequest(hash);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        String hash = SessionManager.getChannelHash(ctx.channel());
        //Server.getInstance().getLogger().debug("server-ChannelInactive: hash=" + hash);
        this.getSessionManager().getServer().addInternalClientCloseRequest(hash);
        this.getSessionManager().getSessions().remove(hash);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof SynapseDataPacket) {
            SynapseDataPacket packet = (SynapseDataPacket) msg;
            String hash = SessionManager.getChannelHash(ctx.channel());
            //Server.getInstance().getLogger().debug("server-ChannelRead: hash=" + hash + " pk=" + packet.getClass().getSimpleName() + " pkLen=" + packet.getBuffer().length);
            this.getSessionManager().getServer().pushThreadToMainPacket(new SynapseClientPacket(hash, packet));
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.throwing(cause);
        ctx.close();
    }
}
