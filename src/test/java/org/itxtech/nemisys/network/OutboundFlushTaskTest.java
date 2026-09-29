package org.itxtech.nemisys.network;

import io.netty.util.concurrent.EventExecutor;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OutboundFlushTaskTest {
    @Test
    void coalescesRequestsAndPreservesFifo() {
        EventExecutor executor = mock(EventExecutor.class);
        Queue<Runnable> tasks = new ArrayDeque<>();
        doAnswer(call -> { tasks.add(call.getArgument(0)); return null; }).when(executor).execute(any());
        Queue<String> packets = new ArrayDeque<>();
        List<String> sent = new ArrayList<>();
        OutboundFlushTask flush = new OutboundFlushTask(executor, () -> {
            String packet;
            while ((packet = packets.poll()) != null) sent.add(packet);
        }, () -> !packets.isEmpty());
        packets.add("first");
        flush.schedule();
        packets.add("second");
        flush.schedule();
        assertEquals(1, tasks.size());
        tasks.remove().run();
        assertEquals(List.of("first", "second"), sent);
        assertTrue(tasks.isEmpty());
    }

    @Test
    void enqueueAtTheEndOfFlushDoesNotLoseWakeup() {
        EventExecutor executor = mock(EventExecutor.class);
        Queue<Runnable> tasks = new ArrayDeque<>();
        doAnswer(call -> { tasks.add(call.getArgument(0)); return null; }).when(executor).execute(any());
        Queue<String> packets = new ArrayDeque<>();
        List<String> sent = new ArrayList<>();
        AtomicBoolean first = new AtomicBoolean(true);
        AtomicReference<OutboundFlushTask> reference = new AtomicReference<>();
        OutboundFlushTask flush = new OutboundFlushTask(executor, () -> {
            String packet;
            while ((packet = packets.poll()) != null) sent.add(packet);
            if (first.getAndSet(false)) {
                packets.add("concurrent");
                reference.get().schedule();
            }
        }, () -> !packets.isEmpty());
        reference.set(flush);
        packets.add("initial");
        flush.schedule();
        tasks.remove().run();
        assertEquals(1, tasks.size());
        tasks.remove().run();
        assertEquals(List.of("initial", "concurrent"), sent);
        assertTrue(tasks.isEmpty());
    }

    @Test
    void rejectedScheduleKeepsDataForPeriodicFallbackAndCanRetry() {
        EventExecutor executor = mock(EventExecutor.class);
        AtomicBoolean reject = new AtomicBoolean(true);
        Queue<Runnable> tasks = new ArrayDeque<>();
        doAnswer(call -> {
            if (reject.getAndSet(false)) throw new RejectedExecutionException("Test rejection");
            tasks.add(call.getArgument(0));
            return null;
        }).when(executor).execute(any());
        Queue<String> packets = new ArrayDeque<>();
        packets.add("retained");
        OutboundFlushTask flush = new OutboundFlushTask(executor, packets::clear, () -> !packets.isEmpty());
        assertDoesNotThrow(flush::schedule);
        assertEquals("retained", packets.peek());
        flush.schedule();
        assertEquals(1, tasks.size());
        tasks.remove().run();
        assertTrue(packets.isEmpty());
    }

    @Test
    void shutdownDoesNotScheduleNewWork() {
        EventExecutor executor = mock(EventExecutor.class);
        when(executor.isShuttingDown()).thenReturn(true);
        new OutboundFlushTask(executor, () -> fail("Unexpected flush"), () -> true).schedule();
        verify(executor, never()).execute(any());
    }
}
