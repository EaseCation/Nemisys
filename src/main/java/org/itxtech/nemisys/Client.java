package org.itxtech.nemisys;

import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;
import it.unimi.dsi.fastutil.Pair;
import it.unimi.dsi.fastutil.objects.ObjectArrayList;
import it.unimi.dsi.fastutil.objects.ObjectIntPair;
import lombok.extern.log4j.Log4j2;
import org.itxtech.nemisys.event.client.ClientAuthEvent;
import org.itxtech.nemisys.event.client.ClientConnectEvent;
import org.itxtech.nemisys.event.client.ClientDisconnectEvent;
import org.itxtech.nemisys.event.client.PluginMsgRecvEvent;
import org.itxtech.nemisys.network.SynapseInterface;
import org.itxtech.nemisys.network.protocol.mcpe.*;
import org.itxtech.nemisys.network.protocol.spp.*;
import org.itxtech.nemisys.network.protocol.spp.DisconnectPacket;
import org.itxtech.nemisys.utils.*;
import org.itxtech.nemisys.utils.ClientData.Entry;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Author: PeratX
 * Nemisys Project
 */
@Log4j2
public class Client {
    private final Server server;
    private final SynapseInterface interfaz;
    private final String ip;
    private final int port;
    private final Map<UUID, Player> players = new ConcurrentHashMap<>();
    private boolean verified = false;
    private boolean isMainServer = false;
    private int maxPlayers;
    private long lastUpdate;
    private String description;
    private float tps;
    private float load;
    private long upTime;
    private long lastUpdatePlayerNetworkLatency;

    public Client(SynapseInterface interfaz, String ip, int port) {
        this.server = interfaz.getServer();
        this.interfaz = interfaz;
        this.ip = ip;
        this.port = port;
        this.lastUpdate = System.currentTimeMillis();

        this.server.getPluginManager().callEvent(new ClientConnectEvent(this));
    }

    public boolean isMainServer() {
        return this.isMainServer;
    }

    public int getMaxPlayers() {
        return this.maxPlayers;
    }

    public String getHash() {
        return this.ip + ':' + this.port;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public float getTicksPerSecond() {
        return this.tps;
    }

    public float getTickUsage() {
        return this.load;
    }

    public long getUpTime() {
        return this.upTime;
    }

    public void onUpdate(int currentTick) {
        if ((System.currentTimeMillis() - this.lastUpdate) >= 30 * 1000) {//30 seconds timeout
            this.close("timeout");
        }
        if (System.currentTimeMillis() - this.lastUpdatePlayerNetworkLatency >= 1000) {
            PlayerLatencyPacket pk = new PlayerLatencyPacket();
            List<ObjectIntPair<UUID>> pings = new ArrayList<>();
            for (Player player : this.players.values()) {
                int ping = player.getPing();
                if (ping != 0) {
                    pings.add(ObjectIntPair.of(player.getSessionId(), ping));
                }
            }
            pk.pings = pings.toArray(new ObjectIntPair[0]);
            this.sendDataPacket(pk);
            this.lastUpdatePlayerNetworkLatency = System.currentTimeMillis();
        }
    }

    public void handleDataPacket(SynapseDataPacket packet) {
        /*this.server.getPluginManager().callEvent(ev = new ClientRecvPacketEvent(this, packet));
        if(ev.isCancelled()){
			return;
		}*/

        switch (packet.pid()) {
            case SynapseInfo.BROADCAST_PACKET:
                GenericPacket gPacket = new GenericPacket();
                gPacket.setBuffer(((BroadcastPacket) packet).payload);
                for (UUID sessionId : ((BroadcastPacket) packet).sessionIds) {
                    Player player = this.players.get(sessionId);
                    if (player != null) {
                        player.sendDataPacket(gPacket);
                    }
                }
                break;
            case SynapseInfo.HEARTBEAT_PACKET:
                if (!this.isVerified()) {
                    this.server.getLogger().error("Client " + this.getIp() + ":" + this.getPort() + " is not verified");
                    return;
                }
                HeartbeatPacket heartbeatPacket = (HeartbeatPacket) packet;
                this.lastUpdate = System.currentTimeMillis();
                //this.server.getLogger().debug("Received Heartbeat Packet from " + this.getIp() + ":" + this.getPort());
                this.tps = heartbeatPacket.tps;
                this.load = heartbeatPacket.load;
                this.upTime = heartbeatPacket.upTime;

                InformationPacket pk = new InformationPacket();
                ClientData clientData = this.server.getClientData();
                Pair<String, Entry>[] clientList = new Pair[clientData.clientList.size()];
                int i = 0;
                for (Map.Entry<String, Entry> entry : clientData.clientList.entrySet()) {
                    clientList[i++] = Pair.of(entry.getKey(), entry.getValue());
                }
                pk.clientList = clientList;
                this.sendDataPacket(pk);
                break;
            case SynapseInfo.CONNECT_PACKET:
                ConnectPacket connectPacket = (ConnectPacket) packet;
                if (connectPacket.protocol != SynapseInfo.CURRENT_PROTOCOL) {
                    this.close("Incompatible SPP version! Require SPP version: " + SynapseInfo.CURRENT_PROTOCOL, true, DisconnectPacket.TYPE_WRONG_PROTOCOL);
                    return;
                }
                ConnectionStatusPacket pk2 = new ConnectionStatusPacket();
                if (this.server.comparePassword(connectPacket.password)) {
                    this.setVerified();
                    pk2.type = ConnectionStatusPacket.TYPE_LOGIN_SUCCESS;
                    this.isMainServer = connectPacket.isMainServer;
                    this.description = connectPacket.description;
                    this.maxPlayers = connectPacket.maxPlayers;
                    this.server.addClient(this);
                    this.server.getLogger().info("Client " + this.getIp() + ":" + this.getPort() + " has connected successfully");
                    this.server.getLogger().info("mainServer: " + (this.isMainServer ? "true" : "false"));
                    this.server.getLogger().info("description: " + this.description);
                    this.server.getLogger().info("maxPlayers: " + this.maxPlayers);
                    this.server.updateClientData();
                    this.sendDataPacket(pk2);
                } else {
                    pk2.type = ConnectionStatusPacket.TYPE_LOGIN_FAILED;
                    log.fatal("Client {}:{} tried to connect with wrong password!", this.getIp(), this.getPort());
                    this.sendDataPacket(pk2);
                    this.close("Auth failed!");
                }
                this.server.getPluginManager().callEvent(new ClientAuthEvent(this, connectPacket.password));
                break;
            case SynapseInfo.DISCONNECT_PACKET:
                this.close(((DisconnectPacket) packet).message, false);
                break;
            case SynapseInfo.REDIRECT_PACKET:
                Player player = this.players.get(((RedirectPacket) packet).sessionId);
                if (player != null) {
                    byte[] buffer = ((RedirectPacket) packet).mcpeBuffer;
                    DataPacket send;
                    if (buffer.length > 0 && buffer[0] == (byte) ProtocolInfo.BATCH_PACKET) {
                        send = new BatchPacket();
//                        send.reliability = RakNetReliability.fromId(((RedirectPacket) packet).reliability);
                        send.setBuffer(buffer, 1);
                        send.decode();
//                        send.setChannel(((RedirectPacket) packet).channel);
                        //if (send.reliability != RakNetReliability.RELIABLE_ORDERED || send.getChannel() != 0)
                        //    this.server.getLogger().info("batch: " + ((RedirectPacket) packet).mcpeBuffer.length + "  reliability: " + send.reliability.name() + "  channel: " + send.getChannel());
                    } else {
                        send = new GenericPacket();
//                        send.reliability = RakNetReliability.fromId(((RedirectPacket) packet).reliability);
//                        send.setChannel(((RedirectPacket) packet).channel);
                        send.setBuffer(((RedirectPacket) packet).mcpeBuffer);
                        //this.server.getLogger().info("len: " + ((RedirectPacket) packet).mcpeBuffer.length + "  reliability: " + send.reliability.name() + "  channel: " + send.getChannel());
                    }

                    player.sendDataPacket(send);
                    //this.server.getLogger().warning("Send to player: " + Binary.bytesToHexString(new byte[]{((RedirectPacket) packet).mcpeBuffer[0]}) + "  len: " + ((RedirectPacket) packet).mcpeBuffer.length);
                }/*else{
					this.server.getLogger().error("Error RedirectPacket 0x" + bin2hex(packet.buffer));
				}*/
                break;
            case SynapseInfo.TRANSFER_PACKET:
                Map<String, Client> clients = this.server.getClients();
                player = this.players.get(((TransferPacket) packet).sessionId);
                if (player != null) {
                    Client client = clients.get(((TransferPacket) packet).clientHash);
                    if (client != null) {
                        player.transfer(client, ((TransferPacket) packet).extra, true);
                    } else {
                        player.close("Synapse Server: " + TextFormat.RED + "Target server is not online!" + "\n" + TextFormat.YELLOW + ((TransferPacket) packet).clientHash);
                    }
                }
                break;
            case SynapseInfo.PLUGIN_MESSAGE_PACKET:
                PluginMessagePacket messagePacket = (PluginMessagePacket) packet;
                DataInput input = new DataInputStream(new ByteArrayInputStream(messagePacket.data));
                String channel = messagePacket.channel;

                PluginMsgRecvEvent ev = new PluginMsgRecvEvent(this, channel, messagePacket.data.clone());
                this.server.getPluginManager().callEvent(ev);

                if (ev.isCancelled()) {
                    break;
                }

                if (channel.equals("Nemisys")) {
                    try {
                        String subChannel = input.readUTF();
                        ByteArrayDataOutput out = ByteStreams.newDataOutput();

                        switch (subChannel) {
                            case "TransferToPlayer":
                                String playerName = input.readUTF();
                                String target = input.readUTF();

                                Player p = this.server.getPlayerExact(playerName);
                                Player p2 = this.server.getPlayerExact(target);

                                if (p == null || p2 == null) {
                                    break;
                                }

                                p.transfer(p2.getClient());
                                break;
                            case "IP":
                                playerName = input.readUTF();

                                p = this.server.getPlayerExact(playerName);

                                if (p == null) {
                                    break;
                                }

                                out.writeUTF("IP");
                                out.writeUTF(this.server.getIp());
                                out.writeInt(this.server.getPort());
                                break;
                            case "PlayerCount":
                                String server = input.readUTF();

                                Client client = this.server.getClient(this.server.getClientData().getHashByDescription(server));

                                if (client == null) {
                                    break;
                                }

                                out.writeUTF("PlayerCount");
                                out.writeUTF(server);
                                out.writeInt(client.getPlayers().size());
                                break;
                            case "GetServers":
                                out.writeUTF("GetServers");

                                List<String> names = new ObjectArrayList<>();
                                this.server.getClients().values().forEach(c -> names.add(c.getDescription()));

                                out.writeUTF(String.join(", ", names));
                                break;
                            case "Message":
                                playerName = input.readUTF();
                                String message = input.readUTF();

                                p = this.server.getPlayerExact(playerName);

                                if (p == null) {
                                    break;
                                }

                                p.sendMessage(message);
                                break;
                            case "MessageAll":
                                message = input.readUTF();

                                TextPacket textPacket = new TextPacket();
                                textPacket.type = TextPacket.TYPE_RAW;
                                textPacket.message = message;

                                Server.broadcastPacket(this.server.getOnlinePlayers().values(), textPacket);
                                break;
                            case "UUID":
                                break;
                            case "KickPlayer":
                                playerName = input.readUTF();
                                String reason = input.readUTF();

                                p = this.server.getPlayerExact(playerName);

                                if (p == null) {
                                    break;
                                }

                                p.close(reason);
                                break;
                        }

                        if (out != null) {
                            byte[] data = out.toByteArray();

                            if (data.length > 0) {
                                this.sendPluginMesssage(channel, data);
                            }
                        }
                    } catch (Exception e) {
                        MainLogger.getLogger().logException(e);
                    }
                }
                break;
            case SynapseInfo.PLAYER_LOGOUT_PACKET:
                PlayerLogoutPacket playerLogoutPacket = (PlayerLogoutPacket) packet;
                player = this.players.get(playerLogoutPacket.sessionId);
                if (player != null) {
                    player.close(playerLogoutPacket.reason, true);
                }
                break;
            default:
                this.server.getLogger().error("Client " + this.getIp() + ":" + this.getPort() + " has sent an unknown packet " + packet.pid());
        }
    }

    public void sendDataPacket(SynapseDataPacket pk) {
        this.interfaz.putPacket(this, pk);
        /*this.server.getPluginManager().callEvent(ev = new ClientSendPacketEvent(this, pk));
		if(!ev.isCancelled()){
			this.interfaz.putPacket(this, pk);
		}*/
    }

    public String getIp() {
        return this.ip;
    }

    public int getPort() {
        return this.port;
    }

    public boolean isVerified() {
        return this.verified;
    }

    public void setVerified() {
        this.verified = true;
    }

    public Map<UUID, Player> getPlayers() {
        return this.players;
    }

    public void addPlayer(Player player) {
        this.players.put(player.getSessionId(), player);
    }

    public void removePlayer(Player player) {
        this.players.remove(player.getSessionId());
    }

    public void closeAllPlayers() {
        this.closeAllPlayers("");
    }

    public void closeAllPlayers(String reason) {
        for (Player player : new ObjectArrayList<>(this.players.values())) {
            player.close("Server Closed" + (reason.isEmpty() ? "" : ": " + TextFormat.YELLOW + reason));
        }
    }

    public void close() {
        this.close("Generic reason");
    }

    public void close(String reason) {
        this.close(reason, true);
    }

    public void close(String reason, boolean needPk) {
        this.close(reason, needPk, DisconnectPacket.TYPE_GENERIC);
    }

    public void close(String reason, boolean needPk, byte type) {
        ClientDisconnectEvent ev;
        this.server.getPluginManager().callEvent(ev = new ClientDisconnectEvent(this, reason, type));
        reason = ev.getReason();
        this.server.getLogger().info("Client " + this.ip + ":" + this.port + " has disconnected due to " + reason);
        if (needPk) {
            DisconnectPacket pk = new DisconnectPacket();
            pk.type = type;
            pk.message = reason;
            this.sendDataPacket(pk);
        }
        this.closeAllPlayers(reason);
        this.interfaz.removeClient(this);
        this.server.removeClient(this);
    }

    public void sendPluginMesssage(String channel, byte[] data) {
        PluginMessagePacket pk = new PluginMessagePacket();
        pk.channel = channel;
        pk.data = data;
        this.sendDataPacket(pk);
    }
}
