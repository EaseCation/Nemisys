package org.itxtech.nemisys.synapse;

import it.unimi.dsi.fastutil.Pair;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;
import it.unimi.dsi.fastutil.objects.ObjectIntPair;
import org.itxtech.nemisys.Nemisys;
import org.itxtech.nemisys.Player;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.event.synapse.player.SynapsePlayerCreationEvent;
import org.itxtech.nemisys.network.Compressor;
import org.itxtech.nemisys.network.NetworkSession;
import org.itxtech.nemisys.network.protocol.mcpe.DataPacket;
import org.itxtech.nemisys.network.protocol.spp.*;
import org.itxtech.nemisys.synapse.network.SynLibInterface;
import org.itxtech.nemisys.synapse.network.SynapseInterface;
import org.itxtech.nemisys.synapse.network.SynapseNetworkSession;
import org.itxtech.nemisys.utils.ClientData;
import org.itxtech.nemisys.utils.ClientData.Entry;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Created by boybook on 16/8/21.
 */
public class SynapseEntry {

    private final Synapse synapse;

    private boolean enable;
    private String serverIp;
    private int port;
    private boolean isMainServer;
    private String password;
    private SynapseInterface synapseInterface;
    private boolean verified = false;
    private long lastUpdate;
    private final Map<UUID, SynapsePlayer> players = new Object2ObjectOpenHashMap<>();
    private SynLibInterface synLibInterface;
    private ClientData clientData;
    private String serverDescription;

    public SynapseEntry(Synapse synapse, String serverIp, int port, boolean isMainServer, String password, String serverDescription) {
        this.synapse = synapse;
        this.serverIp = serverIp;
        this.port = port;
        this.isMainServer = isMainServer;
        this.password = password;
        if (this.password.length() != 16) {
            synapse.getLogger().warning("You must use a 16 bit length key!");
            synapse.getLogger().warning("This SynapseAPI Entry will not be enabled!");
            enable = false;
            return;
        }
        this.serverDescription = serverDescription;

        this.synapseInterface = new SynapseInterface(this, this.serverIp, this.port);
        this.synLibInterface = new SynLibInterface(this.synapseInterface);
        this.lastUpdate = System.currentTimeMillis();
        this.getSynapse().getServer().getScheduler().scheduleRepeatingTask(new Ticker(), 5);
    }

    public static String getRandomString(int length) { //length表示生成字符串的长度
        String base = "abcdefghijklmnopqrstuvwxyz0123456789";
        Random random = ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }

    public Synapse getSynapse() {
        return this.synapse;
    }

    public boolean isEnable() {
        return enable;
    }

    public ClientData getClientData() {
        return clientData;
    }

    public SynapseInterface getSynapseInterface() {
        return synapseInterface;
    }

    public void shutdown() {
        if (this.synapseInterface != null) {
            this.synapseInterface.markClosing();
        }

        if (this.verified) {
            DisconnectPacket pk = new DisconnectPacket();
            pk.type = DisconnectPacket.TYPE_GENERIC;
            pk.message = "Server closed";
            this.sendDataPacket(pk);
            //this.getSynapse().getLogger().debug("Synapse client has disconnected from Synapse synapse");
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                //ignore
            }
        }
        if (this.synapseInterface != null) this.synapseInterface.shutdown();
    }

    public String getServerDescription() {
        return serverDescription;
    }

    public void setServerDescription(String serverDescription) {
        this.serverDescription = serverDescription;
    }

    public void sendDataPacket(SynapseDataPacket pk) {
        this.synapseInterface.putPacket(pk);
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getServerIp() {
        return serverIp;
    }

    public void setServerIp(String serverIp) {
        this.serverIp = serverIp;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void broadcastPacket(SynapsePlayer[] players, DataPacket packet) {
        this.broadcastPacket(players, packet, false);
    }

    public void broadcastPacket(SynapsePlayer[] players, DataPacket packet, boolean direct) {
        packet.encode();
        BroadcastPacket broadcastPacket = new BroadcastPacket();
        broadcastPacket.direct = direct;
        broadcastPacket.payload = packet.getBuffer();
        int length = players.length;
        UUID[] sessionIds = new UUID[length];
        for (int i = 0; i < length; i++) {
            sessionIds[i] = players[i].getSessionId();
        }
        broadcastPacket.sessionIds = sessionIds;
        this.sendDataPacket(broadcastPacket);
    }

    public boolean isMainServer() {
        return isMainServer;
    }

    public void setMainServer(boolean mainServer) {
        isMainServer = mainServer;
    }

    public String getHash() {
        return this.serverIp + ":" + this.port;
    }

    public void connect() {
        this.getSynapse().getLogger().info("Connecting " + this.getHash());
        this.verified = false;
        ConnectPacket pk = new ConnectPacket();
        pk.password = this.password;
        pk.isMainServer = this.isMainServer();
        pk.description = this.serverDescription;
        pk.maxPlayers = this.getSynapse().getServer().getMaxPlayers();
        pk.protocol = SynapseInfo.CURRENT_PROTOCOL;
        this.sendDataPacket(pk);
        /*
        Thread ticker = new Thread(new Ticker());
        ticker.setName("SynapseAPI Ticker");
        ticker.start();
        */
    }

    public void tick() {
        this.synapseInterface.process();
        if (!this.getSynapseInterface().isConnected()) return;
        long time = System.currentTimeMillis();
        if ((time - this.lastUpdate) >= 5000) {//Heartbeat!
            this.lastUpdate = time;
            HeartbeatPacket pk = new HeartbeatPacket();
            pk.tps = this.getSynapse().getServer().getTicksPerSecondAverage();
            pk.load = this.getSynapse().getServer().getTickUsageAverage();
            pk.upTime = (System.currentTimeMillis() - Nemisys.START_TIME) / 1000;
            this.sendDataPacket(pk);
            //this.getSynapse().getServer().getLogger().debug(time + " -> Sending Heartbeat Packet to " + this.getHash());
        }

        long finalTime = System.currentTimeMillis();
        long usedTime = finalTime - time;
        //this.getSynapse().getServer().getLogger().warning(time + " -> tick 用时 " + usedTime + " 毫秒");
        if (((finalTime - this.lastUpdate) >= 30000) && this.synapseInterface.isConnected()) {  //30 seconds timeout
            this.synapseInterface.reconnect();
        }
    }

    public void removePlayer(UUID sessionId) {
        this.players.remove(sessionId);
    }

    public void handleDataPacket(SynapseDataPacket pk) {
        //this.getSynapse().getLogger().warning("Received packet " + pk.pid() + "(" + pk.getClass().getSimpleName() + ") from " + this.serverIp + ":" + this.port);
        switch (pk.pid()) {
            case SynapseInfo.DISCONNECT_PACKET:
                DisconnectPacket disconnectPacket = (DisconnectPacket) pk;
                this.verified = false;
                switch (disconnectPacket.type) {
                    case DisconnectPacket.TYPE_GENERIC:
                        this.getSynapse().getLogger().info("Synapse Client has disconnected due to " + disconnectPacket.message);
                        this.synapseInterface.reconnect();
                        break;
                    case DisconnectPacket.TYPE_WRONG_PROTOCOL:
                        this.getSynapse().getLogger().error(disconnectPacket.message);
                        break;
                }
                break;
            case SynapseInfo.CONNECTION_STATUS_PACKET:
                ConnectionStatusPacket connectionStatusPacket = (ConnectionStatusPacket) pk;
                switch (connectionStatusPacket.type) {
                    case ConnectionStatusPacket.TYPE_LOGIN_SUCCESS:
                        this.getSynapse().getLogger().info("Login success to " + this.serverIp + ":" + this.port);
                        this.verified = true;
                        break;
                    case ConnectionStatusPacket.TYPE_LOGIN_FAILED:
                        this.getSynapse().getLogger().info("Login failed to " + this.serverIp + ":" + this.port);
                        break;
                }
                break;
            case SynapseInfo.INFORMATION_PACKET:
                InformationPacket informationPacket = (InformationPacket) pk;
                ClientData clientData = new ClientData();
                for (Pair<String, Entry> client : informationPacket.clientList) {
                    clientData.clientList.put(client.left(), client.right());
                }
                this.clientData = clientData;
                break;
            case SynapseInfo.PLAYER_LATENCY_PACKET:
                PlayerLatencyPacket playerLatencyPacket = (PlayerLatencyPacket) pk;
                for (ObjectIntPair<UUID> entry : playerLatencyPacket.pings) {
                    SynapsePlayer player = this.players.get(entry.left());
                    if (player != null) {
                        player.latency = entry.rightInt();
                    }
                }
                break;
            case SynapseInfo.PLAYER_LOGIN_PACKET:
                PlayerLoginPacket playerLoginPacket = (PlayerLoginPacket) pk;

                InetSocketAddress socketAddress = InetSocketAddress.createUnresolved(playerLoginPacket.address, playerLoginPacket.port);
                SynapsePlayerCreationEvent ev = new SynapsePlayerCreationEvent(this.synLibInterface, SynapsePlayer.class, SynapsePlayer.class, ThreadLocalRandom.current().nextLong(), socketAddress);
                this.getSynapse().getServer().getPluginManager().callEvent(ev);
                Class<? extends SynapsePlayer> clazz = ev.getPlayerClass();
                try {
                    Constructor<?> constructor = clazz.getConstructor(NetworkSession.class, SynapseEntry.class, Long.class, InetSocketAddress.class, Compressor.class);
                    SynapseNetworkSession session = new SynapseNetworkSession(synLibInterface);
                    SynapsePlayer player = (SynapsePlayer) constructor.newInstance(session, this, ev.getClientId(), ev.getSocketAddress(),
                            playerLoginPacket.protocol >= 407 ? Compressor.ZLIB_RAW : Compressor.ZLIB);
                    session.setPlayer(player);
                    player.setUniqueId(playerLoginPacket.uuid);
                    this.players.put(playerLoginPacket.sessionId, player);
                    this.getSynapse().getServer().addPlayer(socketAddress, player);
                    player.handleLoginPacket(playerLoginPacket);
                } catch (NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException e) {
                    Server.getInstance().getLogger().logException(e);
                }
                break;
            case SynapseInfo.REDIRECT_PACKET:
                RedirectPacket redirectPacket = (RedirectPacket) pk;
                Player player = this.players.get(redirectPacket.sessionId);
                if (player != null) {
                    DataPacket pk0 = this.getSynapse().getPacket(redirectPacket.mcpeBuffer);
                    if (pk0 != null) {
                        pk0.decode();
                        player.handleDataPacket(pk0);
                    } else if (player.getClient() != null) {
                        player.redirectPacket(redirectPacket.mcpeBuffer, redirectPacket.compressionAlgorithm); //player.getClient().sendDataPacket(redirectPacket);
                    }
                }
                break;
            case SynapseInfo.PLAYER_LOGOUT_PACKET:
                PlayerLogoutPacket playerLogoutPacket = (PlayerLogoutPacket) pk;
                UUID sessionId = playerLogoutPacket.sessionId;
                player = this.players.get(sessionId);
                if (player != null) {
                    player.close(playerLogoutPacket.reason, true);
                    this.removePlayer(sessionId);
                }
                break;
        }
    }

    public class Ticker implements Runnable {
        @Override
        public void run() {
            tick();
        }
    }


}
