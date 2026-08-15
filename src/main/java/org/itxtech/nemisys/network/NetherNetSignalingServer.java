package org.itxtech.nemisys.network;

import com.nukkitx.network.util.EventLoops;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Future;

import javax.annotation.Nullable;
import java.net.InetSocketAddress;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class NetherNetSignalingServer {
    private final InetSocketAddress bindAddress;
    private final EventLoopGroup eventLoopGroup;
    private final ChannelGroup channels;

    private final Object lifecycleLock = new Object();
    private volatile boolean closing;
    @Nullable
    private CompletableFuture<Void> bindFuture;
    @Nullable
    private CompletableFuture<Void> closeFuture;

    public NetherNetSignalingServer(InetSocketAddress bindAddress) {
        this.bindAddress = bindAddress;
        this.eventLoopGroup = EventLoops.newEventLoopGroup(1);
        this.channels = new DefaultChannelGroup("nethernet-signaling", this.eventLoopGroup.next(), true);
    }

    public CompletableFuture<Void> start() {
        CompletableFuture<Void> future;
        synchronized (this.lifecycleLock) {
            if (this.bindFuture != null) {
                return this.bindFuture.copy();
            }
            if (this.closing) {
                return CompletableFuture.failedFuture(new IllegalStateException("NetherNet signaling server is closing"));
            }

            future = new CompletableFuture<>();
            this.bindFuture = future;
            try {
                this.eventLoopGroup.next().execute(() -> this.bind(future));
            } catch (Throwable throwable) {
                future.completeExceptionally(throwable);
            }
        }
        return future.copy();
    }

    private void bind(CompletableFuture<Void> future) {
        if (this.closing) {
            future.completeExceptionally(new CancellationException("NetherNet signaling server was closed before binding"));
            return;
        }

        try {
            ServerBootstrap bootstrap = new ServerBootstrap()
                    .group(this.eventLoopGroup)
                    .channel(EventLoops.getChannelType().getServerSocketChannel())
                    .childOption(ChannelOption.SO_LINGER, 0)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel channel) {
                            channels.add(channel);
                            channel.close();
                        }
                    });

            ChannelFuture channelFuture = bootstrap.bind(this.bindAddress);
            this.channels.add(channelFuture.channel());
            channelFuture.addListener(completed -> {
                if (completed.isSuccess()) {
                    future.complete(null);
                } else {
                    Throwable cause = completed.cause();
                    future.completeExceptionally(cause == null ? new CancellationException("NetherNet signaling bind was cancelled") : cause);
                }
            });
        } catch (Throwable throwable) {
            future.completeExceptionally(throwable);
        }
    }

    public CompletableFuture<Void> closeAsync() {
        CompletableFuture<Void> result;
        CompletableFuture<Void> currentBindFuture;
        synchronized (this.lifecycleLock) {
            if (this.closeFuture != null) {
                return this.closeFuture.copy();
            }

            this.closing = true;
            result = new CompletableFuture<>();
            this.closeFuture = result;
            currentBindFuture = this.bindFuture == null ? CompletableFuture.completedFuture(null) : this.bindFuture;
        }

        AtomicReference<Throwable> cleanupFailure = new AtomicReference<>();
        CompletableFuture<Void> bindSettled = currentBindFuture.handle((_, _) -> null);
        CompletableFuture<Void> initialClose = settle(this.closeChannels(), cleanupFailure);

        CompletableFuture.allOf(bindSettled, initialClose)
                .thenCompose(_ -> settle(this.closeChannels(), cleanupFailure))
                .thenCompose(_ -> settle(this.shutdownEventLoopGroup(), cleanupFailure))
                .whenComplete((_, throwable) -> {
                    if (throwable != null) {
                        recordFailure(cleanupFailure, throwable);
                    }
                    Throwable failure = cleanupFailure.get();
                    if (failure == null) {
                        result.complete(null);
                    } else {
                        result.completeExceptionally(failure);
                    }
                });
        return result.copy();
    }

    public boolean isClosing() {
        return this.closing;
    }

    public boolean isInEventLoop() {
        for (EventExecutor executor : this.eventLoopGroup) {
            if (executor.inEventLoop()) {
                return true;
            }
        }
        return false;
    }

    private CompletableFuture<Void> closeChannels() {
        try {
            return toCompletableFuture(this.channels.close());
        } catch (Throwable throwable) {
            return CompletableFuture.failedFuture(throwable);
        }
    }

    private CompletableFuture<Void> shutdownEventLoopGroup() {
        try {
            return toCompletableFuture(this.eventLoopGroup.shutdownGracefully(0, 5, TimeUnit.SECONDS));
        } catch (Throwable throwable) {
            return CompletableFuture.failedFuture(throwable);
        }
    }

    private static CompletableFuture<Void> settle(CompletableFuture<Void> future, AtomicReference<Throwable> failure) {
        return future.handle((_, throwable) -> {
            if (throwable != null) {
                recordFailure(failure, throwable);
            }
            return null;
        });
    }

    private static CompletableFuture<Void> toCompletableFuture(Future<?> nettyFuture) {
        CompletableFuture<Void> future = new CompletableFuture<>();
        nettyFuture.addListener(completed -> {
            if (completed.isSuccess()) {
                future.complete(null);
            } else {
                Throwable cause = completed.cause();
                future.completeExceptionally(cause == null ? new CancellationException() : cause);
            }
        });
        return future;
    }

    private static void recordFailure(AtomicReference<Throwable> failure, Throwable throwable) {
        Throwable cause = unwrapCompletionException(throwable);
        Throwable current = failure.get();
        if (current == null && failure.compareAndSet(null, cause)) {
            return;
        }

        current = failure.get();
        if (current != null && current != cause) {
            current.addSuppressed(cause);
        }
    }

    private static Throwable unwrapCompletionException(Throwable throwable) {
        Throwable cause = throwable;
        while (cause instanceof CompletionException && cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause;
    }
}
