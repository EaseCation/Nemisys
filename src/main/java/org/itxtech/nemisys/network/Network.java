package org.itxtech.nemisys.network;

import org.itxtech.nemisys.Nemisys;
import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.network.protocol.mcpe.*;
import org.itxtech.nemisys.utils.*;
import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class Network {

    private static final ThreadLocal<Inflater> INFLATER_RAW = ThreadLocal.withInitial(() -> new Inflater(true));
    private static final ThreadLocal<Deflater> DEFLATER_RAW = ThreadLocal.withInitial(() -> new Deflater(7, true));
    private static final ThreadLocal<byte[]> BUFFER = ThreadLocal.withInitial(() -> new byte[2 * 1024 * 1024]);

    private Class<? extends DataPacket>[] packetPool = new Class[256];

    private Server server;

    private Set<SourceInterface> interfaces = new HashSet<>();

    private Set<AdvancedSourceInterface> advancedInterfaces = new HashSet<>();

    private double upload = 0;
    private double download = 0;

    private String name;
    private String subName;

    public Network(Server server) {
        this.registerPackets();
        this.server = server;
    }

    public static byte[] inflateRaw(byte[] data) throws IOException, DataFormatException {
        Inflater inflater = INFLATER_RAW.get();
        inflater.reset();
        inflater.setInput(data);
        inflater.finished();

        FastByteArrayOutputStream bos = new FastByteArrayOutputStream(1024);
        bos.reset();
        byte[] buf = BUFFER.get();
        while (!inflater.finished()) {
            int i = inflater.inflate(buf);
            if (i == 0) {
                throw new IOException("Could not decompress the data. Needs input: "+inflater.needsInput()+", Needs Dictionary: "+inflater.needsDictionary());
            }
            bos.write(buf, 0, i);
        }
        return bos.toByteArray();
    }

    public static byte[] deflateRaw(byte[] data, int level) throws IOException {
        Deflater deflater = DEFLATER_RAW.get();
        deflater.reset();
        deflater.setLevel(level);
        deflater.setInput(data);
        deflater.finish();
        FastByteArrayOutputStream bos = new FastByteArrayOutputStream(1024);
        bos.reset();
        byte[] buffer = BUFFER.get();
        while (!deflater.finished()) {
            int i = deflater.deflate(buffer);
            bos.write(buffer, 0, i);
        }

        return bos.toByteArray();
    }

    public static byte[] deflateRaw(byte[][] datas, int level) throws IOException {
        Deflater deflater = DEFLATER_RAW.get();
        deflater.reset();
        deflater.setLevel(level);
        FastByteArrayOutputStream bos = new FastByteArrayOutputStream(1024);
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
        //Deflater::end is called the time when the process exits.
        return bos.toByteArray();
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
                this.server.getLogger().critical(this.server.getLanguage().translateString("nemisys.server.networkError", new String[]{interfaz.getClass().getName(), Utils.getExceptionMessage(e)}));
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

    public void registerPacket(byte id, Class<? extends DataPacket> clazz) {
        this.packetPool[id & 0xff] = clazz;
    }

    public Server getServer() {
        return server;
    }

    public void processBatch(BatchPacket packet, Player player) {
        byte[] data;
        try {
            data = Network.inflateRaw(packet.payload);
        } catch (Exception e) {
            try {
                data = Zlib.inflate(packet.payload, 2 * 1024 * 1024); // Max 2MB
            } catch (Exception e0) {
                return;
            }
        }

        int len = data.length;
        BinaryStream stream = new BinaryStream(data);
        try {
            List<DataPacket> packets = new ArrayList<>();
            int count = 0;
            while (stream.offset < len) {
                count++;
                if (count >= 1000) {
                    player.close("Illegal Batch Packet");
                    return;
                }
                byte[] buf = stream.getByteArray();

                DataPacket pk;

                if ((pk = this.getPacket(buf[0])) != null) {
                    /*System.out.println("first bits: "+buf[1]+"   "+buf[2]);
                    System.out.println("other bits: "+ Arrays.toString(buf));*/
                    pk.setBuffer(buf, 3);

                    try {
                        pk.decode();
                    } catch (Exception e) { //probably 1.1 client ?
                        //e.printStackTrace();
                        pk.setBuffer(buf, 1); //skip 2 more bytes
                        pk.decode();
                    }

                    packets.add(pk);
                }
            }

            processPackets(player, packets);

        } catch (Exception e) {
            if (Nemisys.DEBUG > 0) {
                this.server.getLogger().debug("BatchPacket 0x" + Binary.bytesToHexString(packet.payload));
                this.server.getLogger().logException(e);
            }
        }
    }

    /**
     * Process packets obtained from batch packets
     * Required to perform additional analyses and filter unnecessary packets
     *
     * @param packets
     */
    public void processPackets(Player player, List<DataPacket> packets) {
        if (packets.isEmpty()) return;
        packets.forEach(player::handleDataPacket);
    }


    public DataPacket getPacket(byte id) {
        Class<? extends DataPacket> clazz = this.packetPool[id & 0xff];
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
        this.packetPool = new Class[256];

        this.registerPacket(ProtocolInfo.LOGIN_PACKET, LoginPacket.class);
        this.registerPacket(ProtocolInfo.DISCONNECT_PACKET, DisconnectPacket.class);
        this.registerPacket(ProtocolInfo.BATCH_PACKET, BatchPacket.class);
        this.registerPacket(ProtocolInfo.PLAYER_LIST_PACKET, PlayerListPacket.class);
    }
}
