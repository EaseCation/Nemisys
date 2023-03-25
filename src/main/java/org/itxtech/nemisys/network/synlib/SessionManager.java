package org.itxtech.nemisys.network.synlib;

import io.netty.channel.Channel;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.math.NemisysMath;
import org.itxtech.nemisys.utils.MainLogger;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Author: PeratX
 * Nemisys Project
 */
public class SessionManager {
    private final SynapseServer server;
    private final Map<String, Channel> sessions = new ConcurrentHashMap<>();
    private long nextTick;
    private int tickCounter;
    private final float[] tickAverage = {100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100};
    private final float[] useAverage = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private float maxTick = 100;
    private float maxUse = 0;

    public SessionManager(SynapseServer server) {
        this.server = server;
    }

    public static String getChannelHash(Channel channel) {
        InetSocketAddress address = (InetSocketAddress) channel.remoteAddress();
        return address.getAddress().getHostAddress() + ":" + address.getPort();
    }

    public void run() {
        this.tickProcessor();
        for (Channel channel : this.sessions.values()) {
            channel.close();
        }
    }

    public void tickProcessor() {
        this.nextTick = System.currentTimeMillis();
        while (!this.server.isShutdown()) {
            try {
                this.tick();
            } catch (RuntimeException e) {
                Server.getInstance().getLogger().logException(e);
            } finally {
                long next = this.nextTick;
                long current = System.currentTimeMillis();
                if (next - 0.1 > current) {
                    try {
                        Thread.sleep(next - current - 1, 900000);
                    } catch (InterruptedException ignored) {
                    }
                }
            }
        }
        this.server.bossGroup.shutdownGracefully();
        this.server.workerGroup.shutdownGracefully();
    }

    public Map<String, Channel> getSessions() {
        return this.sessions;
    }

    public SynapseServer getServer() {
        return this.server;
    }

    private boolean sendPacket() {
        SynapseClientPacket data = this.server.readMainToThreadPacket();
        if (data != null) {
            String hash = data.getHash();
            Channel channel = this.sessions.get(hash);
            if (channel != null) {
                channel.writeAndFlush(data.getPacket());
                //Server.getInstance().getLogger().debug("server-writeAndFlush: hash=" + hash);
            }
            return true;
        }
        return false;
    }

    private boolean closeSessions() {
        String hash = this.server.getExternalClientCloseRequest();
        if (hash != null) {
            Channel channel = this.sessions.remove(hash);
            if (channel != null) {
                channel.close();
            }
            return true;
        }
        return false;
    }

    public void tick() {
        long tickTime = System.currentTimeMillis();
        long tickTimeNano = System.nanoTime();
        if ((tickTime - this.nextTick) < -5) {
            return;
        }

        ++this.tickCounter;
        try {
            while (this.sendPacket()) ;
            while (this.closeSessions()) ;
        } catch (Exception e) {
            MainLogger.getLogger().logException(e);
        }

        if ((this.tickCounter & 0b1111) == 0) {
            this.maxTick = 100;
            this.maxUse = 0;
        }

        //long now = System.currentTimeMillis();
        long nowNano = System.nanoTime();
        //float tick = Math.min(100, 1000 / Math.max(1, now - tickTime));
        //float use = Math.min(1, (now - tickTime) / 50);

        float tick = (float) Math.min(100, 1000000000 / Math.max(1000000, ((double) nowNano - tickTimeNano)));
        float use = (float) Math.min(1, ((double) (nowNano - tickTimeNano)) / 50000000);

        if (this.maxTick > tick) {
            this.maxTick = tick;
        }

        if (this.maxUse < use) {
            this.maxUse = use;
        }

        System.arraycopy(this.tickAverage, 1, this.tickAverage, 0, this.tickAverage.length - 1);
        this.tickAverage[this.tickAverage.length - 1] = tick;

        System.arraycopy(this.useAverage, 1, this.useAverage, 0, this.useAverage.length - 1);
        this.useAverage[this.useAverage.length - 1] = use;

        if ((this.nextTick - tickTime) < -1000) {
            this.nextTick = tickTime;
        } else {
            this.nextTick += 10;
        }
    }

    public int getTick() {
        return tickCounter;
    }

    public float getTicksPerSecond() {
        return ((float) Math.round(this.maxTick * 100)) / 100;
    }

    public float getTicksPerSecondAverage() {
        float sum = 0;
        int count = this.tickAverage.length;
        for (float aTickAverage : this.tickAverage) {
            sum += aTickAverage;
        }
        return (float) NemisysMath.round(sum / count, 2);
    }

    public float getTickUsage() {
        return (float) NemisysMath.round(this.maxUse * 100, 2);
    }

    public float getTickUsageAverage() {
        float sum = 0;
        int count = this.useAverage.length;
        for (float aUseAverage : this.useAverage) {
            sum += aUseAverage;
        }
        return ((float) Math.round(sum / count * 100)) / 100;
    }

}
