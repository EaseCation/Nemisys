package org.itxtech.nemisys.network;

import io.netty.util.concurrent.EventExecutor;
import lombok.extern.log4j.Log4j2;

import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/** 合并同一连接的唤醒；执行失败时保留队列，仍可由原定时器处理。 */
@Log4j2
final class OutboundFlushTask implements Runnable {
    private final EventExecutor executor;
    private final Runnable flush;
    private final BooleanSupplier pending;
    private final AtomicBoolean scheduled = new AtomicBoolean();

    OutboundFlushTask(EventExecutor executor, Runnable flush, BooleanSupplier pending) {
        this.executor = executor;
        this.flush = flush;
        this.pending = pending;
    }

    void schedule() {
        if (executor.isShuttingDown() || !scheduled.compareAndSet(false, true)) {
            return;
        }
        try {
            executor.execute(this);
        } catch (RejectedExecutionException exception) {
            scheduled.set(false);
            if (!executor.isShuttingDown()) {
                log.error("Could not schedule outbound flush; keeping the periodic fallback", exception);
            }
        }
    }

    @Override
    public void run() {
        try {
            flush.run();
        } finally {
            scheduled.set(false);
            // 生产者可能在最后一次 poll 之后入队；重检队列防止丢失唤醒。
            if (pending.getAsBoolean()) {
                schedule();
            }
        }
    }
}
