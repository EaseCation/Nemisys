package org.itxtech.nemisys.network;

import com.whirvis.jraknet.Packet;
import com.whirvis.jraknet.RakNetPacket;
import com.whirvis.jraknet.identifier.MinecraftIdentifier;
import com.whirvis.jraknet.protocol.Reliability;
import com.whirvis.jraknet.server.RakNetServer;
import com.whirvis.jraknet.server.RakNetServerListener;
import com.whirvis.jraknet.server.ServerPing;
import com.whirvis.jraknet.session.RakNetClientSession;
import com.whirvis.jraknet.session.RakNetSession;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.itxtech.nemisys.Nemisys;
import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.event.player.PlayerCreationEvent;
import org.itxtech.nemisys.event.server.QueryRegenerateEvent;
import org.itxtech.nemisys.network.protocol.mcpe.BatchPacket;
import org.itxtech.nemisys.network.protocol.mcpe.DataPacket;
import org.itxtech.nemisys.network.protocol.mcpe.ProtocolInfo;
import org.itxtech.nemisys.utils.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * author: boybook
 * Nukkit Project
 */
public class JRakNetInterface implements RakNetServerListener, AdvancedSourceInterface {

    private final Server server;
    private final Map<RakNetClientSession, Player> players = new ConcurrentHashMap<>();
    private final Map<Integer, RakNetClientSession> identifiers = new ConcurrentHashMap<>();
    private final Queue<ReceivedQueuePacket> queue = new LinkedBlockingQueue<>();
    private Network network;
    private RakNetServer raknet;

    public JRakNetInterface(Server server) {
        this.server = server;

        try {
            raknet = new RakNetServer(server.getPort(), Integer.MAX_VALUE);
            raknet.addListener(this);
            raknet.addSelfListener();
            raknet.setBroadcastingEnabled(true);
            raknet.startThreaded();
        } catch (Exception e) {
            server.getLogger().logException(e);
        }
    }

    private class ReceivedQueuePacket {
        private RakNetClientSession session;
        private DataPacket packet;

        private ReceivedQueuePacket(RakNetClientSession session, DataPacket packet){
            this.session = session;
            this.packet = packet;
        }
    }

    @Override
    public void setNetwork(Network network) {
        this.network = network;
    }

    @Override
    public boolean process() {
        ReceivedQueuePacket pk;
        while ((pk = queue.poll()) != null) {
            //在主线程每tick将队列中已解码数据handle
            if (this.players.containsKey(pk.session)) this.players.get(pk.session).handleDataPacket(pk.packet);
        }

        return true;
    }

    @Override
    public void handlePing(ServerPing ping) {
        Server.getInstance().getLogger().debug("PING " + ping.getSender().toString());
    }

    @Override
    public void handleMessage(RakNetClientSession session, RakNetPacket packet, int channel) {
        if (this.players.containsKey(session)) {
            Player player = this.players.get(session);
            DataPacket pk = null;
            byte[] data = packet.array();
            try {
                pk = this.getPacket(data);
                if (pk != null) {
                    pk.decode();
                    //在这里异步解码数据包内容，然后放入队列
                    if (pk instanceof BatchPacket && player.getCachedLoginPacket().length == 0) {
                        for (DataPacket pk0 : decodeIncomingBatch((BatchPacket) pk)) {
                            queue.add(new ReceivedQueuePacket(session, pk0));
                        }
                    } else {
                        player.redirectPacket(pk.getBuffer()); //直接转发！
                        //queue.add(new ReceivedQueuePacket(session, pk));
                    }
                }
            } catch (Exception e) {
                this.server.getLogger().logException(e);
                if (Nemisys.DEBUG > 1 && pk != null) {
                    MainLogger logger = this.server.getLogger();
                    if (logger != null) {
                        logger.debug("Packet " + pk.getClass().getName() + " 0x" + Binary.bytesToHexString(packet.array()));
                        //logger.logException(e);
                    }
                }

                if (this.players.containsKey(session)) {
                    //this.handler.blockAddress(this.players.get(identifier).getIp(), 5);
                }
            }
        }
    }

    protected List<DataPacket> decodeIncomingBatch(BatchPacket packet) {
        byte[] data;
        try {
            data = Zlib.inflate(packet.payload, 64 * 1024 * 1024);
        } catch (Exception e) {
            return new ArrayList<>();
        }

        int len = data.length;
        BinaryStream stream = new BinaryStream(data);
        try {
            List<DataPacket> packets = new ArrayList<>();
            while (stream.offset < len) {
                byte[] buf = stream.getByteArray();

                DataPacket pk;

                if ((pk = this.server.getNetwork().getPacket(buf[0])) != null) {
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
            return packets;
        } catch (Exception e) {
            if (Nemisys.DEBUG > 0) {
                this.server.getLogger().debug("BatchPacket 0x" + Binary.bytesToHexString(packet.payload));
                this.server.getLogger().logException(e);
            }
        }
        return new ArrayList<>();
    }

    @Override
    public void onClientConnect(RakNetClientSession session) {
        PlayerCreationEvent ev = new PlayerCreationEvent(this, Player.class, Player.class, session.getGloballyUniqueId(), session.getAddress());
        this.server.getPluginManager().callEvent(ev);
        Class<? extends Player> clazz = ev.getPlayerClass();

        try {
            Constructor constructor = clazz.getConstructor(SourceInterface.class, long.class, InetSocketAddress.class);
            Player player = (Player) constructor.newInstance(this, ev.getClientId(), ev.getSocketAddress());
            this.players.put(session, player);
            this.identifiers.put(player.rawHashCode(), session);
            this.server.addPlayer(session.getAddress(), player);
        } catch (NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException e) {
            Server.getInstance().getLogger().logException(e);
        }
    }

    @Override
    public void onClientDisconnect(RakNetClientSession session, String reason) {
        if (this.players.containsKey(session)) {
            Player player = this.players.get(session);
            player.close(reason);
        }
    }

    @Override
    public void onThreadException(Throwable throwable) {
        Server.getInstance().getLogger().debug("Thread exception: " + throwable.getMessage());
        throwable.printStackTrace();
    }

    @Override
    public void onHandlerException(InetSocketAddress address, Throwable throwable) {
        Server.getInstance().getLogger().debug("Handler exception: " + throwable.getMessage());
        throwable.printStackTrace();
    }

    @Override
    public void onSessionException(RakNetClientSession session, Throwable throwable) {
        Server.getInstance().getLogger().debug("Session exception: " + throwable.getMessage());
        throwable.printStackTrace();
    }

    @Override
    public int getNetworkLatency(Player player) {
        return (int) this.identifiers.get(player.rawHashCode()).getLastLatency();
    }

    @Override
    public void close(Player player) {
        this.close(player, "unknown reason");
    }

    @Override
    public void close(Player player, String reason) {
        if (this.identifiers.containsKey(player.rawHashCode())) {
            RakNetSession session = this.identifiers.get(player.rawHashCode());
            this.players.remove(session);
            this.identifiers.remove(player.rawHashCode());
        }
    }

    @Override
    public void shutdown() {
        this.raknet.shutdown();
    }

    @Override
    public void emergencyShutdown() {
        this.raknet.shutdown();
    }

    @Override
    public void blockAddress(InetAddress address) {
        this.blockAddress(address, 300);
    }

    @Override
    public void blockAddress(InetAddress address, int timeout) {

    }

    @Override
    public void sendRawPacket(InetSocketAddress socketAddress, ByteBuf payload) {
        raknet.sendNettyMessage(Unpooled.wrappedBuffer(payload), socketAddress);
    }

    @Override
    public void setName(String name) {
        QueryRegenerateEvent info = this.server.getQueryInformation();
        String[] names = name.split("!@#");  //Split double names within the program
        raknet.setIdentifier(
                new MinecraftIdentifier(Utils.rtrim(names[0].replace(";", "\\;"), '\\'),
                        ProtocolInfo.CURRENT_PROTOCOL,
                        ProtocolInfo.MINECRAFT_VERSION_NETWORK,
                        info.getPlayerCount(), info.getMaxPlayerCount(), this.server.getServerUniqueId().getLeastSignificantBits(),
                        (names.length > 1 ? Utils.rtrim(names[1].replace(";", "\\;"), '\\') : ""),
                        "SMP"));
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
        if (this.identifiers.containsKey(player.rawHashCode())) {
            byte[] buffer;
            if (packet.pid() == ProtocolInfo.BATCH_PACKET) {
                buffer = ((BatchPacket) packet).payload;
            } else {
                if (!packet.isEncoded) {
                    packet.encode(player.getProtocol());
                    packet.isEncoded = true;
                }
                buffer = packet.getBuffer();
                try {
                    buffer = Zlib.deflate(
                            Binary.appendBytes(Binary.writeUnsignedVarInt(buffer.length), buffer),
                            /*Server.getInstance().networkCompressionLevel*/7);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            Server.getInstance().getLogger().warning("GAME WRAPPER RAW: " + Binary.bytesToHexString(buffer));
            BatchPacket bp = new BatchPacket();
            bp.setBuffer(Binary.appendBytes((byte) 0xfe, buffer), 1);
            bp.decode();
            for (DataPacket pk0 : decodeIncomingBatch(bp)) {
                if (pk0.getBuffer()[0] == (byte) 0x4c) {
                    Server.getInstance().getLogger().warning("指令数据： " + Binary.bytesToHexString(pk0.getBuffer()));
                    //return 0;
                } else if (pk0.getBuffer()[0] == (byte) 0x02) {
                    Server.getInstance().getLogger().warning("出生！ " + Binary.bytesToHexString(pk0.getBuffer()));
                } else Server.getInstance().getLogger().warning(Binary.bytesToHexString(pk0.getBuffer()));
            }

            this.identifiers.get(player.rawHashCode()).sendMessage(Reliability.RELIABLE, packet.getChannel(), new Packet(Binary.appendBytes((byte) 0xfe, buffer)));
        }

        return null;
    }

    private DataPacket getPacket(byte[] buffer) {
        int start = 0;

        if (buffer[0] == (byte) 0xfe) {
            start++;
        }
        DataPacket data = this.network.getPacket(ProtocolInfo.BATCH_PACKET);

        if (data == null) {
            return null;
        }

        data.setBuffer(buffer, start);

        return data;
    }
}
