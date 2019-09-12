package org.itxtech.nemisys.network;

import com.magicdroidx.raknetty.RakNetServer;
import com.magicdroidx.raknetty.handler.session.Session;
import com.magicdroidx.raknetty.listener.ServerListener;
import com.magicdroidx.raknetty.listener.SessionListenerAdapter;
import com.magicdroidx.raknetty.protocol.raknet.Reliability;
import com.magicdroidx.raknetty.protocol.raknet.session.GameWrapperPacket;
import com.nukkitx.network.raknet.RakNetServerListener;
import io.netty.buffer.ByteBuf;
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
import java.util.Map;
import java.util.Queue;
import java.util.StringJoiner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * author: boybook
 * Nukkit Project
 */
/*public class RakNettyInterface implements RakNetServerListener, AdvancedSourceInterface {

    private final Server server;
    private final Map<InetSocketAddress, Player> players = new ConcurrentHashMap<>();
    private final Map<Integer, InetSocketAddress> identifiers = new ConcurrentHashMap<>();
    private final Map<InetSocketAddress, Integer> identifiersACK = new ConcurrentHashMap<>();
    private final Queue<ReceivedQueuePacket> queue = new LinkedBlockingQueue<>();
    private Network network;
    private RakNetServer raknet;
    private int[] channelCounts = new int[256];

    public RakNettyInterface(Server server) {
        this.server = server;

        try {
            raknet = RakNetServer.bootstrap()
                    .withListener(new ServerListener() {
                        @Override
                        public void onSessionCreated(Session session) {
                            session.setListener(new SessionListenerAdapter() {
                                @Override
                                public void registered(Session session) {
                                    System.out.println(session.address() + " connecting.");
                                    openSession(session.address(), session.getGUID());
                                }

                                @Override
                                public void connected(Session session) {
                                    System.out.println(session.address() + " connected.");
                                }

                                @Override
                                public void packetReceived(Session session, GameWrapperPacket packet) {
                                    System.out.println("Received a GameWrapper Packet: id=" + Binary.bytesToHexString(new byte[]{packet.body[0]}) + " len=" + packet.body.length);
                                    handleGameWrapper(session.address(), packet);
                                }

                                @Override
                                public void disconnected(Session session) {
                                    System.out.println(session.address() + " disconnected.");
                                }
                            });
                        }

                        @Override
                        public void onSessionRemoved(Session session, String reason) {
                            System.out.println("Session closed: " + session.address() + " due to " + reason);
                            closeSession(session.address(), reason);
                        }
                    })
                    .withPort(server.getPort())
                    .start();
        }catch (Exception e){
            server.getLogger().logException(e);
        }
    }

    private class ReceivedQueuePacket {
        private InetSocketAddress address;
        private DataPacket packet;

        private ReceivedQueuePacket(InetSocketAddress address, DataPacket packet){
            this.address = address;
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
            if (this.players.containsKey(pk.address)) this.players.get(pk.address).handleDataPacket(pk.packet);
        }

        return true;
    }

    @Override
    public void closeSession(InetSocketAddress address, String reason) {
        if (this.players.containsKey(address)) {
            Player player = this.players.get(address);
            this.identifiers.remove(player.rawHashCode());
            this.players.remove(address);
            this.identifiersACK.remove(address);
            player.close(reason);
            if (this.raknet.getSessionManager().contains(address)) this.raknet.getSessionManager().get(address).close(reason);
        }
    }

    @Override
    public int getNetworkLatency(Player player) {
        return this.raknet.getSessionManager().get(this.identifiers.get(player.rawHashCode())).getTimeOut();
    }

    @Override
    public void close(Player player) {
        this.close(player, "unknown reason");
    }

    @Override
    public void close(Player player, String reason) {
        if (this.identifiers.containsKey(player.rawHashCode())) {
            InetSocketAddress address = this.identifiers.get(player.rawHashCode());
            this.closeSession(address, reason);
            this.players.remove(address);
            this.identifiersACK.remove(address);
            this.identifiers.remove(player.rawHashCode());
        }
    }

    @Override
    public void shutdown() {
        this.raknet.stop();
    }

    @Override
    public void emergencyShutdown() {
        this.raknet.stop();
    }

    @Override
    public void openSession(InetSocketAddress address, long clientID) {
        PlayerCreationEvent ev = new PlayerCreationEvent(this, Player.class, Player.class, clientID, address);
        this.server.getPluginManager().callEvent(ev);
        Class<? extends Player> clazz = ev.getPlayerClass();

        try {
            Constructor constructor = clazz.getConstructor(SourceInterface.class, long.class, InetSocketAddress.class);
            Player player = (Player) constructor.newInstance(this, ev.getClientId(), ev.getSocketAddress());
            this.players.put(address, player);
            this.identifiersACK.put(address, 0);
            this.identifiers.put(player.rawHashCode(), address);
            this.server.addPlayer(address, player);
        } catch (NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException e) {
            Server.getInstance().getLogger().logException(e);
        }
    }

    @Override
    public void handleGameWrapper(InetSocketAddress address, GameWrapperPacket packet) {
        if (this.players.containsKey(address)) {
            DataPacket pk = null;
            try {
                if (packet.body.length > 0) {
                    pk = this.getPacket(packet.body);
                    if (pk != null) {
                        pk.decode();
                        //在这里异步解码数据包内容，然后放入队列
                        queue.add(new ReceivedQueuePacket(address, pk));
                    }
                }
            } catch (Exception e) {
                this.server.getLogger().logException(e);
                if (Nemisys.DEBUG > 1 && pk != null) {
                    MainLogger logger = this.server.getLogger();
                    if (logger != null) {
                        logger.debug("Packet " + pk.getClass().getName() + " 0x" + Binary.bytesToHexString(packet.body));
                        //logger.logException(e);
                    }
                }

                if (this.players.containsKey(address)) {
                    //this.handler.blockAddress(this.players.get(identifier).getIp(), 5);
                }
            }
        }
    }

    @Override
    public void blockAddress(InetAddress address) {
        this.blockAddress(address, 300);
    }

    @Override
    public void blockAddress(InetAddress address, int timeout) {
        //this.handler.blockAddress(address, timeout);
    }

    @Override
    public void handleRaw(InetAddress address, ByteBuf payload) {
        this.server.handlePacket(address, payload);
    }

    @Override
    public void sendRawPacket(InetAddress address, ByteBuf payload) {
        //this.handler.sendRaw(address, payload);
    }

    @Override
    public void notifyACK(InetSocketAddress address, int identifierACK) {

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
                .add(this.server.getServerUniqueId().toString())
                .add(subMotd)
                .add("Survival")
                .add("1");
        this.raknet.setName(joiner.toString());
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
                            Binary.appendBytes(Binary.writeUnsignedVarInt(buffer.length), buffer),*/
                            /*Server.getInstance().networkCompressionLevel*//*7);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            GameWrapperPacket gameWrapperPacket = new GameWrapperPacket();
            gameWrapperPacket.body = buffer;//packet.getBuffer();
            gameWrapperPacket.compressed = true;
            this.raknet.getSessionManager().get(this.identifiers.get(player.rawHashCode()))
                    .sendPacket(gameWrapperPacket, Reliability.RELIABLE, immediate);
        }

        return null;
    }

    private DataPacket getPacket(byte[] buffer) {
        BinaryStream stream = new BinaryStream(buffer);

        DataPacket data = this.network.getPacket((byte) stream.getUnsignedVarInt());
        stream.getByte();

        if (data == null) {
            return null;
        }

        data.setBuffer(buffer, stream.offset + 1);

        return data;
    }
}
*/