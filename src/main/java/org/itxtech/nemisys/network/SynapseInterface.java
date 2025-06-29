package org.itxtech.nemisys.network;

import org.itxtech.nemisys.Client;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.network.protocol.spp.*;
import org.itxtech.nemisys.network.synlib.SynapseClientPacket;
import org.itxtech.nemisys.network.synlib.SynapseServer;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by boybook on 16/6/24.
 */
public class SynapseInterface {

    private static final SynapseDataPacket[] packetPool = new SynapseDataPacket[SynapseInfo.COUNT];
    private final Server server;
    private final String ip;
    private final int port;
    private final Map<String, Client> clients = new ConcurrentHashMap<>();
    private final SynapseServer interfaz;

    public SynapseInterface(Server server, String ip, int port) {
        this.server = server;
        this.ip = ip;
        this.port = port;
        this.interfaz = new SynapseServer(server.getLogger(), this, port, ip);
    }

    public static SynapseDataPacket getPacket(byte pid, byte[] buffer) {
        if (pid < 0 || pid >= SynapseInfo.COUNT) {
            return null;
        }

        SynapseDataPacket clazz = packetPool[pid];
        if (clazz != null) {
            SynapseDataPacket pk = clazz.clone();
            pk.setBuffer(buffer, 0);
            return pk;
        }
        return null;
    }

    private static void registerPacket(byte id, SynapseDataPacket packet) {
        packetPool[id] = packet;
    }

    public SynapseServer getInterface() {
        return this.interfaz;
    }

    public Server getServer() {
        return server;
    }

    public void addClient(String ip, int port) {
        this.clients.put(ip + ":" + port, new Client(this, ip, port));
    }

    public void removeClient(Client client) {
        this.interfaz.addExternalClientCloseRequest(client.getHash());
        this.clients.remove(client.getHash());
    }

    public void putPacket(Client client, SynapseDataPacket pk) {
        if (!pk.isEncoded) {
            pk.encode();
        }
        this.interfaz.pushMainToThreadPacket(new SynapseClientPacket(client.getHash(), pk));
    }

    private boolean openClients() {
        String open = this.interfaz.getClientOpenRequest();
        if (open != null) {
            String[] arr = open.split(":");
            this.addClient(arr[0], Integer.parseInt(arr[1]));
            return true;
        }
        return false;
    }

    private boolean processPackets() {
        SynapseClientPacket pk = this.interfaz.readThreadToMainPacket();
        if (pk != null) {
            this.handlePacket(pk.getHash(), pk.getPacket());
            return true;
        }
        return false;
    }

    private boolean closeClients() {
        String close = this.interfaz.getInternalClientCloseRequest();
        if (close != null) {
            Client client = this.clients.remove(close);
            if (client != null) {
                client.close();
            }
            return true;
        }
        return false;
    }

    public void process() {
        while (this.openClients()) ;
        while (this.processPackets()) ;
        while (this.closeClients()) ;
    }

    public void handlePacket(String hash, SynapseDataPacket pk) {
        Client client = this.clients.get(hash);
        if (client == null) {
            return;
        }
        if (pk != null) {
            pk.decode();
            client.handleDataPacket(pk);
        } else {
            this.server.getLogger().critical("Error packet");
        }
    }

    static {
        registerPacket(SynapseInfo.HEARTBEAT_PACKET, new HeartbeatPacket());
        registerPacket(SynapseInfo.CONNECT_PACKET, new ConnectPacket());
        registerPacket(SynapseInfo.DISCONNECT_PACKET, new DisconnectPacket());
        registerPacket(SynapseInfo.REDIRECT_PACKET, new RedirectPacket());
        registerPacket(SynapseInfo.PLAYER_LOGIN_PACKET, new PlayerLoginPacket());
        registerPacket(SynapseInfo.PLAYER_LOGOUT_PACKET, new PlayerLogoutPacket());
        registerPacket(SynapseInfo.INFORMATION_PACKET, new InformationPacket());
        registerPacket(SynapseInfo.TRANSFER_PACKET, new TransferPacket());
        registerPacket(SynapseInfo.BROADCAST_PACKET, new BroadcastPacket());
        registerPacket(SynapseInfo.CONNECTION_STATUS_PACKET, new ConnectionStatusPacket());
        registerPacket(SynapseInfo.PLUGIN_MESSAGE_PACKET, new PluginMessagePacket());
        registerPacket(SynapseInfo.PLAYER_LATENCY_PACKET, new PlayerLatencyPacket());
    }
}
