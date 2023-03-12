package org.itxtech.nemisys.network;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nukkitx.natives.sha256.Sha256;
import com.nukkitx.natives.util.Natives;
import com.nukkitx.network.raknet.*;
import com.nukkitx.network.util.DisconnectReason;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.EventLoop;
import io.netty.channel.socket.DatagramPacket;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.FastThreadLocal;
import io.netty.util.internal.PlatformDependent;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import it.unimi.dsi.fastutil.objects.ObjectArrayList;
import it.unimi.dsi.fastutil.objects.ObjectOpenHashSet;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.message.FormattedMessage;
import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.event.player.PlayerCreationEvent;
import org.itxtech.nemisys.event.server.QueryRegenerateEvent;
import org.itxtech.nemisys.network.protocol.mcpe.BatchPacket;
import org.itxtech.nemisys.network.protocol.mcpe.DataPacket;
import org.itxtech.nemisys.network.protocol.mcpe.NetworkSettingsPacket;
import org.itxtech.nemisys.network.protocol.mcpe.ProtocolInfo;
import org.itxtech.nemisys.network.protocol.mcpe.ServerToClientHandshakePacket;
import org.itxtech.nemisys.utils.Binary;
import org.itxtech.nemisys.utils.BinaryStream;
import org.itxtech.nemisys.utils.EncryptionUtils;
import org.itxtech.nemisys.utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
@Log4j2
public class RakNetInterface implements RakNetServerListener, AdvancedSourceInterface {
    private static final int INCOMING_PACKET_BATCH_PER_TICK = 2; // usually max 1 per tick, but transactions may arrive separately
    private static final int INCOMING_PACKET_BATCH_MAX_BUDGET = 100 * INCOMING_PACKET_BATCH_PER_TICK; // enough to account for a 5-second lag spike

    private final Server server;

    private Network network;

    private final RakNetServer raknet;

    private final Map<InetSocketAddress, NemisysRakNetSession> sessions = new Object2ObjectOpenHashMap<>();

    private final Queue<NemisysRakNetSession> sessionCreationQueue = PlatformDependent.newMpscQueue();


    private final Set<ScheduledFuture<?>> tickFutures = new ObjectOpenHashSet<>();

    private final FastThreadLocal<Set<NemisysRakNetSession>> sessionsToTick = new FastThreadLocal<Set<NemisysRakNetSession>>() {
        @Override
        protected Set<NemisysRakNetSession> initialValue() {
            return Collections.newSetFromMap(new IdentityHashMap<>());
        }
    };

    private byte[] advertisement;

    private static final KeyPair SERVER_KEY_PAIR = EncryptionUtils.createKeyPair();

    private static final ThreadLocal<Sha256> HASH_LOCAL = ThreadLocal.withInitial(Natives.SHA_256);
    private static final ThreadLocal<byte[]> CHECKSUM_LOCAL = ThreadLocal.withInitial(() -> new byte[8]);

    public RakNetInterface(Server server) {
        this.server = server;

        InetSocketAddress bindAddress = new InetSocketAddress(Strings.isNullOrEmpty(this.server.getIp()) ? "0.0.0.0" : this.server.getIp(), this.server.getPort());

        this.raknet = new RakNetServer(bindAddress, Runtime.getRuntime().availableProcessors());
        this.raknet.bind().join();
        this.raknet.setListener(this);

        for (EventExecutor executor : this.raknet.getBootstrap().config().group()) {
            this.tickFutures.add(executor.scheduleAtFixedRate(() -> {
                for (NemisysRakNetSession session : sessionsToTick.get()) {
                    session.sendOutbound();
                }
            }, 0, 50, TimeUnit.MILLISECONDS));
        }
    }

    @Override
    public void setNetwork(Network network) {
        this.network = network;
    }

    @Override
    public boolean process() {
        NemisysRakNetSession session;
        while ((session = this.sessionCreationQueue.poll()) != null) {
            session.lastPacketBudgetUpdateTimeNs = System.nanoTime();

            InetSocketAddress address = session.raknet.getAddress();
            PlayerCreationEvent ev = new PlayerCreationEvent(this, Player.class, Player.class, -1, address);
            this.server.getPluginManager().callEvent(ev);
            Class<? extends Player> clazz = ev.getPlayerClass();

            try {
                Constructor<? extends Player> constructor = clazz.getConstructor(SourceInterface.class, long.class, InetSocketAddress.class, Compressor.class);
                Player player = constructor.newInstance(this, ev.getClientId(), ev.getSocketAddress(), session.compressor);
                this.server.addPlayer(address, player);
                session.player = player;
                this.sessions.put(address, session);
            } catch (NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException e) {
                Server.getInstance().getLogger().logException(e);
            }
        }

        Iterator<NemisysRakNetSession> iterator = this.sessions.values().iterator();
        while (iterator.hasNext()) {
            NemisysRakNetSession nemisysSession = iterator.next();
            Player player = nemisysSession.player;
            if (nemisysSession.disconnectReason != null) {
                player.close(nemisysSession.disconnectReason, false);
                iterator.remove();
                continue;
            }

            DataPacket packet;
            while ((packet = nemisysSession.inbound.poll()) != null && nemisysSession.readable) {
                if (nemisysSession.incomingPacketBatchBudget <= 0) {
                    long nowNs = System.nanoTime();
                    long timeSinceLastUpdateNs = nowNs - nemisysSession.lastPacketBudgetUpdateTimeNs;
                    if (timeSinceLastUpdateNs > 50_000_000) {
                        int ticksSinceLastUpdate = (int) (timeSinceLastUpdateNs / 50_000_000);
                        // If the server takes an abnormally long time to process a tick, add the budget for time difference to compensate.
                        // This extra budget may be very large, but it will disappear the next time a normal update occurs.
                        // This ensures that backlogs during a large lag spike don't cause everyone to get kicked.
                        // As long as all the backlogged packets are processed before the next tick, everything should be OK for clients behaving normally.
                        nemisysSession.incomingPacketBatchBudget = Math.min(nemisysSession.incomingPacketBatchBudget, INCOMING_PACKET_BATCH_MAX_BUDGET) + INCOMING_PACKET_BATCH_PER_TICK * 2 * ticksSinceLastUpdate;
                        nemisysSession.lastPacketBudgetUpdateTimeNs = nowNs;
                    }

                    if (nemisysSession.incomingPacketBatchBudget <= 0) {
                        log.warn("{} receiving packets too fast", player.getName());
                        //TODO: 远程日志上报
                        player.close("Receiving packets too fast");
                        break;
                    }
                }
                nemisysSession.incomingPacketBatchBudget--;

                try {
                    nemisysSession.player.handleDataPacket(packet);
                } catch (Exception e) {
                    log.error(new FormattedMessage("An error occurred whilst handling {} for {}",
                            new Object[]{packet.getClass().getSimpleName(), nemisysSession.player.getName()}, e));
                }
            }
        }
        return true;
    }

    @Override
    public int getNetworkLatency(Player player) {
        RakNetServerSession session = this.raknet.getSession(player.getSocketAddress());
        return session == null ? -1 : (int) session.getPing();
    }

    @Override
    public void close(Player player) {
        this.close(player, "unknown reason");
    }

    @Override
    public void close(Player player, String reason) {
        RakNetServerSession session = this.raknet.getSession(player.getSocketAddress());
        if (session != null) {
            session.close();
        }
    }

    @Override
    public void shutdown() {
        this.tickFutures.forEach(future -> future.cancel(false));
        this.raknet.close();
    }

    @Override
    public void emergencyShutdown() {
        this.tickFutures.forEach(future -> future.cancel(false));
        this.raknet.close();
    }

    @Override
    public void blockAddress(InetAddress address) {
        this.raknet.block(address);
    }

    @Override
    public void blockAddress(InetAddress address, int timeout) {
        this.raknet.block(address, timeout, TimeUnit.SECONDS);
    }

    @Override
    public void sendRawPacket(InetSocketAddress socketAddress, ByteBuf payload) {
        this.raknet.send(socketAddress, payload);
    }

    @Override
    public void setName(String name) {
        QueryRegenerateEvent info = this.server.getQueryInformation();
        String[] names = name.split("!@#");  //Split double names within the program
        String motd = Utils.rtrim(names[0].replace(";", "\\;"), '\\');
        String subMotd = names.length > 1 ? Utils.rtrim(names[1].replace(";", "\\;"), '\\') : "";
        StringJoiner joiner = new StringJoiner(";")
                .add("MCPE")
                .add(motd)
                .add(Integer.toString(ProtocolInfo.CURRENT_PROTOCOL))
                .add(ProtocolInfo.MINECRAFT_VERSION_NETWORK)
                .add(Integer.toString(info.getPlayerCount()))
                .add(Integer.toString(info.getMaxPlayerCount()))
                .add(Long.toString(this.raknet.getGuid()))
                .add(subMotd)
                .add("Survival")
                .add("1");

        this.advertisement = joiner.toString().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public Integer putPacket(Player player, DataPacket packet) {
        return this.putPacket(player, packet, false);
    }

    @Override
    public Integer putPacket(Player player, DataPacket packet, boolean needACK) {
        return this.putPacket(player, packet, needACK, false);
    }

    @Override
    public Integer putPacket(Player player, DataPacket packet, boolean needACK, boolean immediate) {
        NemisysRakNetSession session = this.sessions.get(player.getSocketAddress());

        if (session != null) {
            packet.tryEncode();
            session.outbound.offer(packet);
        }

        return null;
    }

    @Override
    public boolean onConnectionRequest(InetSocketAddress inetSocketAddress) {
        return true;
    }

    @Override
    public byte[] onQuery(InetSocketAddress inetSocketAddress) {
        return this.advertisement;
    }

    @Override
    public void onSessionCreation(RakNetServerSession session) {
        NemisysRakNetSession nemisysSession = new NemisysRakNetSession(session, session.getProtocolVersion() >= 11
                ? Compressor.NONE : session.getProtocolVersion() == 10
                ? Compressor.ZLIB_RAW : /*Compressor.ZLIB*/Compressor.ZLIB_UNKNOWN); // stupid netease...
        session.setListener(nemisysSession);
        this.sessionCreationQueue.offer(nemisysSession);

        // We need to make sure this gets put into the correct thread local hashmap
        // for ticking or race conditions will occur.
        session.getEventLoop().execute(() -> {
            this.sessionsToTick.get().add(nemisysSession);
        });
    }

    @Override
    public void onUnhandledDatagram(ChannelHandlerContext ctx, DatagramPacket datagramPacket) {
        this.server.handlePacket(datagramPacket.sender(), datagramPacket.content());
    }

    public void closeReader(Player player) {
        NemisysRakNetSession session = this.sessions.get(player.getSocketAddress());
        if (session != null) {
            session.readable = false;
        }
    }

    public void setupSettings(Player player, NetworkSettingsPacket settings) {
        NemisysRakNetSession session = this.sessions.get(player.getSocketAddress());
        if (session != null) {
            session.setupSettings(settings, player.getProtocol());
        }
    }

    public void enableEncryption(Player player) {
        NemisysRakNetSession session = this.sessions.get(player.getSocketAddress());
        if (session != null) {
            session.enableEncryption(player.getLoginChainData().getIdentityPublicKey(), player.getProtocol());
        }
    }

    private class NemisysRakNetSession implements RakNetSessionListener {
        private final RakNetServerSession raknet;
        private final Queue<DataPacket> inbound = PlatformDependent.newSpscQueue();
        private final Queue<DataPacket> outbound = PlatformDependent.newMpscQueue();
        private volatile boolean readable = true;
        private String disconnectReason = null;
        private Player player;

        private volatile Compressor compressor;
        private volatile SecretKey secretKey;
        private volatile Cipher encryptCipher;
        private volatile Cipher decryptCipher;
        private final AtomicLong encryptCounter = new AtomicLong();
        private final AtomicLong decryptCounter = new AtomicLong();

        /**
         * At most this many more packets can be received.
         * If this reaches zero, any additional packets received will cause the player to be kicked from the server.
         * This number is increased every tick up to a maximum limit.
         *
         * @see #INCOMING_PACKET_BATCH_PER_TICK
         * @see #INCOMING_PACKET_BATCH_MAX_BUDGET
         */
        private int incomingPacketBatchBudget = INCOMING_PACKET_BATCH_MAX_BUDGET;
        private long lastPacketBudgetUpdateTimeNs;

        private NemisysRakNetSession(RakNetServerSession raknet, Compressor compressor) {
            this.raknet = raknet;
            this.compressor = compressor;
        }

        @Override
        public void onSessionChangeState(RakNetState rakNetState) {

        }

        @Override
        public void onPreDisconnect(DisconnectReason reason) {
            this.readable = false;

            EventLoop eventLoop = this.raknet.getEventLoop();
            if (eventLoop.inEventLoop()) {
                this.sendOutbound();
            } else {
                eventLoop.execute(this::sendOutbound);
            }
        }

        @Override
        public void onDisconnect(DisconnectReason disconnectReason) {
            if (disconnectReason == DisconnectReason.TIMED_OUT) {
                this.disconnect("Timed out");
            } else {
                this.disconnect("Disconnected from Server");
            }

            SecretKey secretKey = this.secretKey;
            if (secretKey != null && !secretKey.isDestroyed()) {
                try {
                    secretKey.destroy();
                } catch (DestroyFailedException ignored) {
                }
            }
        }

        @Override
        public void onEncapsulated(EncapsulatedPacket packet) {
            if (!this.readable) {
                return;
            }

            ByteBuf buffer = packet.getBuffer();
            short packetId = buffer.readUnsignedByte();
            if (packetId == 0xfe && buffer.isReadable()) {
                Cipher decryptCipher = this.decryptCipher;
                if (decryptCipher != null) {
                    // This method only supports contiguous buffers, not composite.
                    ByteBuffer inBuffer = buffer.internalNioBuffer(buffer.readerIndex(), buffer.readableBytes());
                    ByteBuffer outBuffer = inBuffer.duplicate();
                    // Copy-safe so we can use the same buffer.
                    try {
                        decryptCipher.update(inBuffer, outBuffer);
                    } catch (GeneralSecurityException e) {
                        this.disconnect("Bad decrypt");
                        log.debug("Unable to decrypt packet", e);
                        return;
                    }

                    // Verify the checksum
                    buffer.markReaderIndex();
                    int trailerIndex = buffer.writerIndex() - 8;
                    byte[] checksum = CHECKSUM_LOCAL.get();
                    try {
                        buffer.readerIndex(trailerIndex);
                        buffer.readBytes(checksum);
                    } catch (Exception e) {
                        this.disconnect("Bad checksum");
                        log.debug("Unable to verify checksum", e);
                        return;
                    }
                    ByteBuf payload = buffer.slice(1, trailerIndex - 1);
                    long count = this.decryptCounter.getAndIncrement();
                    byte[] expected = this.calculateChecksum(count, payload);
                    for (int i = 0; i < 8; i++) {
                        if (checksum[i] != expected[i]) {
                            this.disconnect("Invalid checksum");
                            log.debug("Encrypted packet {} has invalid checksum (expected {}, got {})",
                                    count, Binary.bytesToHexString(expected), Binary.bytesToHexString(checksum));
                            return;
                        }
                    }
                    buffer.resetReaderIndex();
                }

                if (!buffer.isReadable()) {
                    return;
                }

                // 为了负载均衡, 不在nemisys解包
                /*byte[] packetBuffer = new byte[buffer.readableBytes()];
                buffer.readBytes(packetBuffer);

                try {
                    RakNetInterface.this.network.processBatch(packetBuffer, this.inbound);
                } catch (ProtocolException e) {
                    this.disconnect("Sent malformed packet");
                    log.error("Unable to process batch packet", e);
                }*/

                // 直接丢给nukkit
                DataPacket batchPacket = RakNetInterface.this.network.getServerboundPacket(ProtocolInfo.BATCH_PACKET);
                if (batchPacket == null) {
                    return;
                }

                int length = buffer.readableBytes();
                byte[] packetBuffer = new byte[1 + length];
                packetBuffer[0] = (byte) 0xfe; // 头不要丢了哦
                buffer.readBytes(packetBuffer, 1, length);
                batchPacket.setBuffer(packetBuffer, 1);
                batchPacket.decode();

                this.inbound.offer(batchPacket);
            }
        }

        @Override
        public void onDirect(ByteBuf byteBuf) {
            // We don't allow any direct packets so ignore.
        }

        private void disconnect(String message) {
            this.disconnectReason = message;
            RakNetInterface.this.sessionsToTick.get().remove(this);
        }

        private void sendOutbound() {
            List<DataPacket> toBatch = new ObjectArrayList<>();
            DataPacket packet;
            while ((packet = this.outbound.poll()) != null) {
                if (packet.pid() == ProtocolInfo.BATCH_PACKET) {
                    if (!toBatch.isEmpty()) {
                        this.sendPackets(toBatch);
                        toBatch.clear();
                    }

                    this.sendPacket(((BatchPacket) packet).payload);
                } else {
                    toBatch.add(packet);
                }
            }

            if (!toBatch.isEmpty()) {
                this.sendPackets(toBatch);
            }
        }

        private void sendPackets(Collection<DataPacket> packets) {
            this.sendPackets(packets, true);
        }

        private void sendPackets(Collection<DataPacket> packets, boolean encrypt) {
            this.sendPackets(packets, encrypt, this.compressor);
        }

        private void sendPackets(Collection<DataPacket> packets, boolean encrypt, Compressor compressor) {
            BinaryStream batched = new BinaryStream();
            for (DataPacket packet : packets) {
                Preconditions.checkArgument(!(packet instanceof BatchPacket), "Cannot batch BatchPacket");
                Preconditions.checkState(packet.isEncoded, "Packet should have already been encoded");
                byte[] buf = packet.getBuffer();
                batched.putUnsignedVarInt(buf.length);
                batched.put(buf);
            }

            try {
                this.sendPacket(compressor.compress(batched.getBuffer(), server.getNetworkCompressionLevel()), encrypt);
            } catch (IOException e) {
                log.error("Unable to compress batched packets", e);
            }
        }

        private void sendPacket(byte[] payload) {
            this.sendPacket(payload, true);
        }

        private void sendPacket(byte[] payload, boolean encrypt) {
            ByteBuf byteBuf = ByteBufAllocator.DEFAULT.ioBuffer(1 + payload.length + 8);
            byteBuf.writeByte(0xfe);
            Cipher encryptCipher = this.encryptCipher;
            if (encryptCipher != null && encrypt) {
                ByteBuf compressed = Unpooled.wrappedBuffer(payload);
                try {
                    ByteBuffer checksum = ByteBuffer.wrap(this.calculateChecksum(this.encryptCounter.getAndIncrement(), compressed));

                    ByteBuffer outBuffer = byteBuf.internalNioBuffer(1, compressed.readableBytes() + 8);
                    ByteBuffer inBuffer = compressed.internalNioBuffer(compressed.readerIndex(), compressed.readableBytes());

                    try {
                        encryptCipher.update(inBuffer, outBuffer);
                        encryptCipher.update(checksum, outBuffer);
                    } catch (GeneralSecurityException e) {
                        throw new RuntimeException("Unable to encrypt packet", e);
                    }
                    byteBuf.writerIndex(byteBuf.writerIndex() + compressed.readableBytes() + 8);
                } finally {
                    compressed.release();
                }
            } else {
                byteBuf.writeBytes(payload);
            }
            this.raknet.send(byteBuf);
        }

        private synchronized void setupSettings(NetworkSettingsPacket settings, int protocol) {
            Compressor compressor = settings.compressionThreshold == 0 ? Compressor.NONE
                    : protocol >= 554 && settings.compressionAlgorithm == NetworkSettingsPacket.ALGORITHM_SNAPPY ? Compressor.SNAPPY
                    : protocol >= 407 ? Compressor.ZLIB_RAW : Compressor.ZLIB;
            this.compressor = compressor;
            player.setCompressor(compressor);

            settings.tryEncode(protocol);
            this.sendPackets(Collections.singletonList(settings), protocol < 554, protocol >= 554 ? Compressor.NONE
                    : protocol >= 407 ? Compressor.ZLIB_RAW : Compressor.ZLIB);
        }

        private synchronized void enableEncryption(String clientPublicKey, int protocol) {
            byte[] token = EncryptionUtils.generateRandomToken();

            JWSObject jwt;
            SecretKey secretKey;
            try {
                jwt = EncryptionUtils.createHandshakeJwt(SERVER_KEY_PAIR, token);
                secretKey = EncryptionUtils.getSecretKey(SERVER_KEY_PAIR.getPrivate(), EncryptionUtils.generateKey(clientPublicKey), token);
            } catch (JOSEException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }

            if (!secretKey.getAlgorithm().equals("AES")) {
                throw new IllegalArgumentException("Invalid key algorithm");
            }
            if (this.encryptCipher != null || this.decryptCipher != null) {
                throw new IllegalStateException("Encryption has already been enabled");
            }

            boolean useGcm = protocol > 428;
            this.encryptCipher = EncryptionUtils.createCipher(useGcm, true, secretKey);
            this.decryptCipher = EncryptionUtils.createCipher(useGcm, false, secretKey);
            this.secretKey = secretKey;

            ServerToClientHandshakePacket handshake = new ServerToClientHandshakePacket();
            handshake.jwt = jwt.serialize();
            handshake.tryEncode(protocol);
            // This is sent in cleartext to complete the Diffie Hellman key exchange.
            this.sendPackets(Collections.singletonList(handshake), false);
        }

        private byte[] calculateChecksum(long count, ByteBuf payload) {
            Sha256 hash = HASH_LOCAL.get();
            ByteBuf counterBuf = ByteBufAllocator.DEFAULT.directBuffer(8);
            try {
                counterBuf.writeLongLE(count);
                ByteBuffer keyBuffer = ByteBuffer.wrap(this.secretKey.getEncoded());

                hash.update(counterBuf.internalNioBuffer(0, 8));
                hash.update(payload.internalNioBuffer(payload.readerIndex(), payload.readableBytes()));
                hash.update(keyBuffer);
                byte[] digested = hash.digest();
                return Arrays.copyOf(digested, 8);
            } finally {
                counterBuf.release();
                hash.reset();
            }
        }
    }
}
