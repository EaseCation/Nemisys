package org.itxtech.nemisys.network;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.util.concurrent.FastThreadLocal;
import it.unimi.dsi.fastutil.objects.ObjectArrayList;
import it.unimi.dsi.fastutil.objects.ObjectOpenHashSet;
import lombok.extern.log4j.Log4j2;
import org.itxtech.nemisys.Nemisys;
import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.network.protocol.mcpe.*;
import org.itxtech.nemisys.utils.*;
import io.netty.buffer.ByteBuf;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.util.*;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
@Log4j2
public class Network {

    private static final FastThreadLocal<Inflater> INFLATER_RAW = new FastThreadLocal<>() {
        @Override
        protected Inflater initialValue() {
            return new Inflater(true);
        }
    };
    private static final FastThreadLocal<Deflater> DEFLATER_RAW = new FastThreadLocal<>() {
        @Override
        protected Deflater initialValue() {
            return new Deflater(Deflater.BEST_SPEED, true);
        }
    };
    private static final FastThreadLocal<byte[]> BUFFER = new FastThreadLocal<>() {
        @Override
        protected byte[] initialValue() {
            return new byte[2 * 1024 * 1024];
        }
    };

    private final Class<? extends DataPacket>[] packetPool = new Class[ProtocolInfo.PACKET_COUNT];
    private final Class<? extends DataPacket>[] serverboundPacketPool = new Class[ProtocolInfo.PACKET_COUNT];

    private final Server server;

    private final Set<SourceInterface> interfaces = new ObjectOpenHashSet<>();

    private final Set<AdvancedSourceInterface> advancedInterfaces = new ObjectOpenHashSet<>();

    private double upload = 0;
    private double download = 0;

    private String name;
    private String subName;

    public Network(Server server) {
        this.registerPackets();
        this.server = server;
    }

    public static byte[] inflateRaw(byte[] data, int maxSize) throws IOException, DataFormatException {
        if (data.length == 0) {
            throw new DataLengthException("no data");
        }
        if (maxSize > 0 && data.length >= maxSize) {
            throw new DataLengthException("Input data exceeds maximum size");
        }
        Inflater inflater = INFLATER_RAW.get();
        try {
            inflater.setInput(data);
            inflater.finished();

            FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
            bos.reset();

            byte[] buf = BUFFER.get();
            int length = 0;
            while (!inflater.finished()) {
                int i = inflater.inflate(buf);
                if (i == 0) {
                    throw new IOException("Could not decompress the data. Needs input: " + inflater.needsInput() + ", Needs Dictionary: " + inflater.needsDictionary());
                }
                length += i;
                if (maxSize > 0 && length >= maxSize) {
                    throw new DataLengthException("Inflated data exceeds maximum size");
                }
                bos.write(buf, 0, i);
            }
            return bos.toByteArray();
        } finally {
            inflater.reset();
        }
    }

    public static byte[] deflateRaw(byte[] data, int level) throws IOException {
        Deflater deflater = DEFLATER_RAW.get();
        try {
            deflater.setLevel(level);
            deflater.setInput(data);
            deflater.finish();
            FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
            bos.reset();
            byte[] buffer = BUFFER.get();
            while (!deflater.finished()) {
                int i = deflater.deflate(buffer);
                bos.write(buffer, 0, i);
            }

            return bos.toByteArray();
        } finally {
            deflater.reset();
        }
    }

    public static byte[] deflateRaw(byte[][] datas, int level) throws IOException {
        Deflater deflater = DEFLATER_RAW.get();
        try {
            deflater.setLevel(level);
            FastByteArrayOutputStream bos = ThreadCache.fbaos.get();
            bos.reset();
            byte[] buffer = BUFFER.get();

            for (byte[] data : datas) {
                deflater.setInput(data);
                while (!deflater.needsInput()) {
                    int i = deflater.deflate(buffer);
                    bos.write(buffer, 0, i);
                }
            }
            deflater.finish();
            while (!deflater.finished()) {
                int i = deflater.deflate(buffer);
                bos.write(buffer, 0, i);
            }
            return bos.toByteArray();
        } finally {
            deflater.reset();
        }
    }

    public void addStatistics(double upload, double download) {
        this.upload += upload;
        this.download += download;
    }

    public double getUpload() {
        return upload;
    }

    public double getDownload() {
        return download;
    }

    public void resetStatistics() {
        this.upload = 0;
        this.download = 0;
    }

    public Set<SourceInterface> getInterfaces() {
        return interfaces;
    }

    public void processInterfaces() {
        for (SourceInterface interfaz : this.interfaces) {
            try {
                interfaz.process();
            } catch (Exception e) {
                if (Nemisys.DEBUG > 1) {
                    this.server.getLogger().logException(e);
                }

                interfaz.emergencyShutdown();
                this.unregisterInterface(interfaz);
                this.server.getLogger().critical(this.server.getLanguage().translateString("nemisys.server.networkError", new String[]{interfaz.getClass().getName()}), e);
            }
        }
    }

    public void registerInterface(SourceInterface interfaz) {
        this.interfaces.add(interfaz);
        if (interfaz instanceof AdvancedSourceInterface) {
            this.advancedInterfaces.add((AdvancedSourceInterface) interfaz);
            ((AdvancedSourceInterface) interfaz).setNetwork(this);
        }
        interfaz.setName(this.name + "!@#" + this.subName);
    }

    public void unregisterInterface(SourceInterface sourceInterface) {
        this.interfaces.remove(sourceInterface);
        if (sourceInterface instanceof AdvancedSourceInterface) {
            this.advancedInterfaces.remove(sourceInterface);
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
        this.updateName();
    }

    public String getSubName() {
        return subName;
    }

    public void setSubName(String subName) {
        this.subName = subName;
    }

    public void updateName() {
        for (SourceInterface interfaz : this.interfaces) {
            interfaz.setName(this.name + "!@#" + this.subName);
        }
    }

    public void registerPacket(int id, Class<? extends DataPacket> clazz) {
        registerPacket(id, clazz, false);
    }

    public void registerPacket(int id, Class<? extends DataPacket> clazz, boolean serverbound) {
        this.packetPool[id] = clazz;
        if (serverbound) {
            serverboundPacketPool[id] = clazz;
        }
    }

    public Server getServer() {
        return server;
    }

    public void processBatch(BatchPacket packet, Player player, Compressor compressor) {
        List<DataPacket> packets = new ObjectArrayList<>();
        boolean valid;
        try {
            valid = processBatch(packet.payload, packets, compressor);
        } catch (ProtocolException e) {
            player.close(e.getMessage());
            log.error("Unable to process player packets ", e);
            return;
        }
        if (!valid) {
            player.close("malformed packet");
            return;
        }
        processPackets(player, packets);
    }

    public boolean processBatch(byte[] payload, Collection<DataPacket> packets, Compressor compressor) throws ProtocolException {
        byte[] data;
        try {
            data = compressor.decompress(payload);
        } catch (Exception e) {
//            log.debug("Exception while inflating batch packet", e0);
            return false;
        }
        if (data.length == 0) {
            return false;
        }

        BinaryStream stream = new BinaryStream(data);
        int count = 0;
        try {
            while (!stream.feof()) {
                count++;
                if (count >= 1300) {
//                    throw new ProtocolException("Illegal batch with " + count + " packets");
                    return false;
                }
                byte[] buf = stream.getByteArray();

                ByteArrayInputStream bais = new ByteArrayInputStream(buf);
                int header = (int) VarInt.readUnsignedVarInt(bais);

                // | Client ID | Sender ID | Packet ID |
                // |   2 bits  |   2 bits  |  10 bits  |
                int packetId = header & 0x3ff;

                DataPacket pk = this.getServerboundPacket(packetId);

                if (pk != null) {
                    if (pk.pid() == ProtocolInfo.BATCH_PACKET) {
//                        throw new ProtocolException("nested batch");
                        return false;
                    }

                    /*System.out.println("first bits: "+buf[1]+"   "+buf[2]);
                    System.out.println("other bits: "+ Arrays.toString(buf));*/

                    pk.setBuffer(buf, buf.length - bais.available());
                    try {
                        pk.decode();
                    } catch (Exception e) { //probably 1.1 client ?
                        //e.printStackTrace();
                        try {
                            pk.setBuffer(buf, 1); //skip 2 more bytes
                            pk.decode();
                        } catch (Exception e0) {
                            if (log.isTraceEnabled()) {
                                log.trace("Dumping Packet\n{}", ByteBufUtil.prettyHexDump(Unpooled.wrappedBuffer(buf)));
                            }
                            log.error("Unable to decode packet", e);
//                            throw new IllegalStateException("Unable to decode " + pk.getClass().getSimpleName());
                            return false;
                        }
                    }

                    packets.add(pk);
                } else {
//                    log.debug("Received unknown packet with ID: {}", Integer.toHexString(packetId));
                }
            }
            return true;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error whilst decoding batch packet", e);
            }
        }
        return false;
    }

    /**
     * Process packets obtained from batch packets
     * Required to perform additional analyses and filter unnecessary packets
     *
     * @param packets
     */
    public void processPackets(Player player, List<DataPacket> packets) {
        if (packets.isEmpty()) return;
        packets.forEach(packet -> {
            try {
                player.handleDataPacket(packet);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error whilst handling data packet", e);
                }
            }
        });
    }

    public DataPacket getPacket(int id) {
        Class<? extends DataPacket> clazz = this.packetPool[id];
        if (clazz != null) {
            try {
                return clazz.newInstance();
            } catch (Exception e) {
                Server.getInstance().getLogger().logException(e);
            }
        }
        return new GenericPacket();
    }

    public DataPacket getServerboundPacket(int id) {
        Class<? extends DataPacket> clazz = this.serverboundPacketPool[id];
        if (clazz != null) {
            try {
                return clazz.newInstance();
            } catch (Exception e) {
                Server.getInstance().getLogger().logException(e);
            }
        }
        return new GenericPacket();
    }

    public void sendPacket(InetSocketAddress socketAddress, ByteBuf payload) {
        for (AdvancedSourceInterface sourceInterface : this.advancedInterfaces) {
            sourceInterface.sendRawPacket(socketAddress, payload);
        }
    }

    public void blockAddress(InetAddress address) {
        for (AdvancedSourceInterface sourceInterface : this.advancedInterfaces) {
            sourceInterface.blockAddress(address);
        }
    }

    public void blockAddress(InetAddress address, int timeout) {
        for (AdvancedSourceInterface sourceInterface : this.advancedInterfaces) {
            sourceInterface.blockAddress(address, timeout);
        }
    }

    private void registerPackets() {
        this.registerPacket(ProtocolInfo.LOGIN_PACKET, LoginPacket.class, true);
        this.registerPacket(ProtocolInfo.CLIENT_TO_SERVER_HANDSHAKE_PACKET, ClientToServerHandshakePacket.class, true);
        this.registerPacket(ProtocolInfo.DISCONNECT_PACKET, DisconnectPacket.class);
        this.registerPacket(ProtocolInfo.BATCH_PACKET, BatchPacket.class, true);
        this.registerPacket(ProtocolInfo.PLAYER_LIST_PACKET, PlayerListPacket.class);
//        this.registerPacket(ProtocolInfo.PACKET_VIOLATION_WARNING_PACKET, PacketViolationWarningPacket.class, true);
        this.registerPacket(ProtocolInfo.REQUEST_NETWORK_SETTINGS_PACKET, RequestNetworkSettingsPacket.class, true);
    }
}
