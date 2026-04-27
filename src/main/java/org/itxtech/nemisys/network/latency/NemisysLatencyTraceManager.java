package org.itxtech.nemisys.network.latency;

import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.network.protocol.spp.RedirectTraceData;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 保存 Nemisys 侧最近一次下行探针，给对应上行 pong 透传 trace 数据。
 */
public final class NemisysLatencyTraceManager {
    private static final long EXPIRE_NS = 10_000_000_000L;
    private final Map<UUID, RedirectTraceData> activeTraces = new ConcurrentHashMap<>();

    public void markDownstreamReceive(Player player, RedirectTraceData traceData) {
        if (player == null || traceData == null) {
            return;
        }
        RedirectTraceData copy = traceData.copy();
        copy.mark(RedirectTraceData.NEMISYS_DOWN_RECEIVE, System.nanoTime());
        activeTraces.put(player.getSessionId(), copy);
    }

    public RedirectTraceData markDownstreamQueue(Player player, RedirectTraceData traceData) {
        if (player == null || traceData == null) {
            return null;
        }
        RedirectTraceData copy = traceData.copy();
        copy.mark(RedirectTraceData.NEMISYS_DOWN_QUEUE, System.nanoTime());
        activeTraces.put(player.getSessionId(), copy);
        return copy;
    }

    public RedirectTraceData markDownstreamFlush(Player player, RedirectTraceData traceData) {
        if (player == null || traceData == null) {
            return null;
        }
        RedirectTraceData copy = traceData.copy();
        copy.mark(RedirectTraceData.NEMISYS_DOWN_FLUSH, System.nanoTime());
        activeTraces.put(player.getSessionId(), copy);
        return copy;
    }

    public RedirectTraceData markUpstreamReceive(Player player) {
        RedirectTraceData traceData = getActiveTrace(player);
        if (traceData == null) {
            return null;
        }
        RedirectTraceData copy = traceData.copy();
        copy.mark(RedirectTraceData.NEMISYS_UP_RECEIVE, System.nanoTime());
        activeTraces.put(player.getSessionId(), copy);
        return copy;
    }

    public RedirectTraceData markUpstreamProcess(Player player, RedirectTraceData traceData) {
        if (player == null || traceData == null) {
            return null;
        }
        RedirectTraceData copy = traceData.copy();
        copy.mark(RedirectTraceData.NEMISYS_UP_PROCESS, System.nanoTime());
        activeTraces.put(player.getSessionId(), copy);
        return copy;
    }

    public RedirectTraceData markUpstreamSend(Player player, RedirectTraceData traceData) {
        if (player == null || traceData == null) {
            return null;
        }
        RedirectTraceData copy = traceData.copy();
        copy.mark(RedirectTraceData.NEMISYS_UP_SEND, System.nanoTime());
        return copy;
    }

    private RedirectTraceData getActiveTrace(Player player) {
        if (player == null) {
            return null;
        }
        RedirectTraceData traceData = activeTraces.get(player.getSessionId());
        if (traceData == null) {
            return null;
        }
        long created = traceData.times[RedirectTraceData.NUKKIT_DOWN_SEND];
        if (created > 0 && System.nanoTime() - created > EXPIRE_NS) {
            activeTraces.remove(player.getSessionId());
            return null;
        }
        return traceData;
    }
}
