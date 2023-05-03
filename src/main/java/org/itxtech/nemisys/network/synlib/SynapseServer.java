package org.itxtech.nemisys.network.synlib;

import com.nukkitx.network.util.Bootstraps;
import com.nukkitx.network.util.EventLoops;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.ChannelOption;
import lombok.extern.log4j.Log4j2;
import org.itxtech.nemisys.InterruptibleThread;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.network.SynapseInterface;
import org.itxtech.nemisys.network.protocol.spp.SynapseInfo;
import org.itxtech.nemisys.utils.ThreadedLogger;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

@Log4j2
public class SynapseServer extends Thread implements InterruptibleThread {

    public static final String VERSION = "0.3.0";

    protected final ConcurrentLinkedQueue<SynapseClientPacket> externalQueue;
    protected final ConcurrentLinkedQueue<SynapseClientPacket> internalQueue;
    protected final ConcurrentLinkedQueue<String> clientOpenQueue;
    protected final ConcurrentLinkedQueue<String> internalClientCloseQueue;
    protected final ConcurrentLinkedQueue<String> externalClientCloseQueue;
    private final ThreadedLogger logger;
    private final String interfaz;
    private final int port;
    private final AtomicBoolean shutdown;
    private final SynapseInterface server;
    private final SessionManager sessionManager;

    public SynapseServer(ThreadedLogger logger, SynapseInterface server, int port) {
        this(logger, server, port, "0.0.0.0");
    }

    public SynapseServer(ThreadedLogger logger, SynapseInterface server, int port, String interfaz) {
        this.logger = logger;
        this.server = server;
        this.interfaz = interfaz;
        this.port = port;
        if (port < 1 || port > 65536) {
            throw new IllegalArgumentException("Invalid port range");
        }
        this.shutdown = new AtomicBoolean();
        this.externalQueue = new ConcurrentLinkedQueue<>();
        this.internalQueue = new ConcurrentLinkedQueue<>();
        this.clientOpenQueue = new ConcurrentLinkedQueue<>();
        this.internalClientCloseQueue = new ConcurrentLinkedQueue<>();
        this.externalClientCloseQueue = new ConcurrentLinkedQueue<>();
        this.sessionManager = new SessionManager(this);

        this.start();
    }

    public ConcurrentLinkedQueue<SynapseClientPacket> getExternalQueue() {
        return externalQueue;
    }

    public ConcurrentLinkedQueue<SynapseClientPacket> getInternalQueue() {
        return internalQueue;
    }

    public String getInternalClientCloseRequest() {
        return this.internalClientCloseQueue.poll();
    }

    public void addInternalClientCloseRequest(String hash) {
        this.internalClientCloseQueue.add(hash);
    }

    public String getExternalClientCloseRequest() {
        return this.externalClientCloseQueue.poll();
    }

    public void addExternalClientCloseRequest(String hash) {
        this.externalClientCloseQueue.add(hash);
    }

    public String getClientOpenRequest() {
        return this.clientOpenQueue.poll();
    }

    public void addClientOpenRequest(String hash) {
        this.clientOpenQueue.add(hash);
    }

    public boolean isShutdown() {
        return shutdown.get();
    }

    public void shutdown() {
        this.shutdown.compareAndSet(false, true);
    }

    public int getPort() {
        return port;
    }

    public String getInterface() {
        return interfaz;
    }

    public ThreadedLogger getLogger() {
        return logger;
    }

    public void pushMainToThreadPacket(SynapseClientPacket data) {
        this.internalQueue.offer(data);
    }

    public SynapseClientPacket readMainToThreadPacket() {
        return this.internalQueue.poll();
    }

    public void pushThreadToMainPacket(SynapseClientPacket data) {
        if (data.getPacket().pid() == SynapseInfo.REDIRECT_PACKET) {
            server.handlePacket(data.getHash(), data.getPacket()); //把nk发给玩家的数据包绕过主线程，直接在netty线程中进行发送
        } else {
            this.externalQueue.offer(data);
        }
    }

    public SynapseClientPacket readThreadToMainPacket() {
        return this.externalQueue.poll();
    }

    @Override
    public void run() {
        this.setName("SynLib Thread #" + Thread.currentThread().getId());
        Runtime.getRuntime().addShutdownHook(new ShutdownHandler());
        try {
            if (this.bind()) {
                this.sessionManager.run();
            } else {
                Server.getInstance().shutdown();
            }
        } catch (Exception e) {
            Server.getInstance().getLogger().logException(e);
        }
    }

    public boolean bind() {
        try {
            ServerBootstrap b = new ServerBootstrap();  //服务引导程序，服务器端快速启动程序
            b.option(ChannelOption.ALLOCATOR, ByteBufAllocator.DEFAULT);
            Bootstraps.setupServerBootstrap(b);
            b.group(EventLoops.commonGroup())
                    .option(ChannelOption.SO_BACKLOG, 1024)
                    .childOption(ChannelOption.SO_KEEPALIVE, true)
                    .childHandler(new SynapseServerInitializer(this.sessionManager));

            b.bind(this.interfaz, this.port).get();
            // 等待服务端监听端口关闭，等待服务端链路关闭之后main函数才退出
            //future.channel().closeFuture().sync();
            return true;
        } catch (Exception e) {
            log.warn("Synapse Server can't bind to: {}:{}", this.interfaz, this.port, e);
            log.warn("Server will shutdown.");
            return false;
        }
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    private class ShutdownHandler extends Thread {
        @Override
        public void run() {
            if (!shutdown.get()) {
                log.fatal("SynLib crashed!");
            }
        }
    }
}
