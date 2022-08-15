package org.itxtech.nemisys;

import com.google.gson.JsonObject;
import org.itxtech.nemisys.event.player.PlayerAsyncLoginEvent;
import org.itxtech.nemisys.event.player.PlayerLoginEvent;
import org.itxtech.nemisys.event.player.PlayerLogoutEvent;
import org.itxtech.nemisys.event.player.PlayerTransferEvent;
import org.itxtech.nemisys.network.RakNetInterface;
import org.itxtech.nemisys.network.SourceInterface;
import org.itxtech.nemisys.network.protocol.mcpe.*;
import org.itxtech.nemisys.network.protocol.spp.PlayerLoginPacket;
import org.itxtech.nemisys.network.protocol.spp.PlayerLogoutPacket;
import org.itxtech.nemisys.network.protocol.spp.RedirectPacket;
import org.itxtech.nemisys.scheduler.AsyncTask;
import org.itxtech.nemisys.utils.*;

import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Author: PeratX
 * Nemisys Project
 */
public class Player {
    public boolean closed;
    protected UUID uuid;
    private byte[] cachedLoginPacket = new byte[0];
    protected String name;
    private InetSocketAddress socketAddress;
    private long clientId;
    private long randomClientId;
    private String xuid;
    private int protocol;
    private SourceInterface interfaz;
    private Client client;
    private Server server;
    private byte[] rawUUID;
    protected boolean isFirstTimeLogin = true;
    private long lastUpdate;
    private Skin skin;
    private LoginChainData loginChainData;
    protected boolean neteaseClient;
    protected String hideName;

    private final AtomicBoolean ticking = new AtomicBoolean();

    private AsyncTask preLoginEventTask = null;

    protected final Queue<DataPacket> incomingPackets = new ConcurrentLinkedQueue<>();
    protected final Queue<DataPacket> outgoingPackets = new ConcurrentLinkedQueue<>();

    public Player(SourceInterface interfaz, long clientId, InetSocketAddress socketAddress) {
        this.interfaz = interfaz;
        this.clientId = clientId;
        this.socketAddress = socketAddress;
        this.name = "";
        this.server = Server.getInstance();
        this.lastUpdate = System.currentTimeMillis();
    }

    public byte[] getCachedLoginPacket() {
        return cachedLoginPacket;
    }

    public long getClientId() {
        return this.clientId;
    }

    public UUID getUniqueId() {
        return this.uuid;
    }

    public byte[] getRawUUID() {
        return this.rawUUID;
    }

    public Server getServer() {
        return this.server;
    }

    public void handleDataPacket(DataPacket packet) {
        if (this.closed) {
            return;
        }
        this.lastUpdate = System.currentTimeMillis();

        switch (packet.pid()) {
            case ProtocolInfo.BATCH_PACKET:
                if (this.cachedLoginPacket.length == 0) {
                    this.getServer().getNetwork().processBatch((BatchPacket) packet, this);
                } else {
                    if (this.client != null) this.redirectPacket(packet.getBuffer());
                }
                break;
            case ProtocolInfo.LOGIN_PACKET:
                LoginPacket loginPacket = (LoginPacket) packet;
                this.cachedLoginPacket = loginPacket.cacheBuffer;
                this.skin = loginPacket.skin;
                this.name = loginPacket.username;
                this.protocol = loginPacket.protocol;
                if (this.protocol <= 113) {
                    this.loginChainData = ClientChainDataNetEase.read(loginPacket);
                    if (this.loginChainData.getClientUUID() != null) {  //网易认证通过！
                        this.neteaseClient = true;
                    } else {  //国际版普通认证
                        this.loginChainData = ClientChainData11.read(loginPacket);
                        this.neteaseClient = false;
                    }
                } else {
                    this.loginChainData = ClientChainDataNetEase.read(loginPacket);
                    if (this.loginChainData.getClientUUID() != null) {  //网易认证通过！
                        this.neteaseClient = true;
                    } else {  //国际版普通认证
                        try {
                            this.loginChainData = ClientChainData.read(loginPacket);
                            if (protocol >= 160 && !loginChainData.isXboxAuthed() && server.getPropertyBoolean("xbox-auth", false)) {
                                this.close("disconnectionScreen.notAuthenticated");
                            }
                        } catch (Exception e) {
                            this.getServer().getLogger()
                                    .notice(this.name + TextFormat.RED + " 解析时出现问题，采用紧急解析方案！" + e.getMessage());
                            this.loginChainData = ClientChainDataUrgency.read(loginPacket);
                        }
                        this.neteaseClient = false;
                    }
                }

                if (this.server.isNetworkEncryptionEnabled()) {
                    this.setupNetworkEncryption();
                }

                this.uuid = this.loginChainData.getClientUUID();
                if (this.uuid == null) {
                    this.close(TextFormat.RED + "Please choose another name and try again!");
                    break;
                }
                this.xuid = this.loginChainData.getXUID();
                this.rawUUID = Binary.writeUUID(this.uuid);
                this.randomClientId = this.loginChainData.getClientId();

                if (this.protocol <= 113) {
                    this.close(TextFormat.YELLOW + "Sorry, we do not support version 1.1 now!\nplease update your game version to at least 1.2!\n抱歉，现已不再支持1.1版本，请更新您的游戏到至少1.2！");
                    return;
                }

                this.server.getLogger().info(this.getServer().getLanguage().translateString("nemisys.player.logIn", new String[]{
                        TextFormat.AQUA + this.name + TextFormat.WHITE,
                        this.getIp(),
                        String.valueOf(this.getPort()),
                        "" + TextFormat.GREEN + this.getUUID() + TextFormat.WHITE,
                }));

                Map<String, Client> c = this.server.getMainClients();

                String clientHash;
                if (c.size() > 0) {
                    clientHash = new ArrayList<>(c.keySet()).get(new Random().nextInt(c.size()));
                } else {
                    clientHash = "";
                }

                PlayerLoginEvent ev;
                this.server.getPluginManager().callEvent(ev = new PlayerLoginEvent(this, "Plugin Reason"));
                if (ev.isCancelled()) {
                    this.close(ev.getKickMessage());
                    break;
                }
                if (this.server.getMaxPlayers() <= this.server.getOnlinePlayers().size()) {
                    //this.close("Synapse Server: " + TextFormat.RED + "Synapse server is full!");
                    this.close("服务器现在压力山大T_T" + TextFormat.YELLOW + " 为了保证游戏体验，请稍后再试下哦:D");
                    break;
                }

                PlayerAsyncLoginEvent event = new PlayerAsyncLoginEvent(this, clientHash);

                this.preLoginEventTask = new AsyncTask() {

                    private PlayerAsyncLoginEvent e;

                    @Override
                    public void onRun() {
                        e = event;
                        server.getPluginManager().callEvent(e);
                    }

                    @Override
                    public void onCompletion(Server server) {
                        if (!closed) {
                            if (e.getLoginResult() == PlayerAsyncLoginEvent.LoginResult.KICK) {
                                close(e.getKickMessage());
                            } else {
                                completeLoginSequence(e.getTransferClientHash());
                            }
                        }
                    }
                };

                this.server.getScheduler().scheduleAsyncTask(this.preLoginEventTask);


                break;
            default:
                if (this.client != null) this.redirectPacket(packet.getBuffer());
        }
    }

    public void completeLoginSequence(String clientHash) {
        if (clientHash == null || clientHash.equals("")) {
            this.close("Synapse Server: " + TextFormat.RED + "No target server!");
            return;
        }
        if (!this.server.getClients().containsKey(clientHash)) {
            this.close("Synapse Server: " + TextFormat.RED + "Target server is not online!");
            return;
        }
        this.transfer(this.server.getClients().get(clientHash));
    }

    public void redirectPacket(byte[] buffer) {
        RedirectPacket pk = new RedirectPacket();
        pk.protocol = this.protocol;
        pk.uuid = this.uuid;
        pk.direct = false;
        pk.mcpeBuffer = buffer;
        this.client.sendDataPacket(pk);
    }

    public boolean canTick() {
        return !this.ticking.get();
    }

    public void onUpdate(long currentTick) {

    }

    public String getIp() {
        return this.socketAddress.isUnresolved() ? this.socketAddress.getHostName() : this.socketAddress.getAddress().getHostAddress();
    }

    public int getPort() {
        return this.socketAddress.getPort();
    }

    public InetSocketAddress getSocketAddress() {
        return this.socketAddress;
    }

    public UUID getUUID() {
        return this.uuid;
    }

    public String getName() {
        return this.name;
    }

    public String getHideName() {
        return hideName;
    }

    public void setHideName(String hideName) {
        this.hideName = hideName;
    }

    public void removeAllPlayers() {
        PlayerListPacket pk = new PlayerListPacket();
        pk.type = PlayerListPacket.TYPE_REMOVE;
        List<PlayerListPacket.Entry> entries = new ArrayList<>();
        for (Player p : this.client.getPlayers().values()) {
            if (p == this) {
                continue;
            }
            entries.add(new PlayerListPacket.Entry(p.getUUID()));
        }

        pk.entries = entries.toArray(new PlayerListPacket.Entry[0]);
        this.sendDataPacket(pk);
    }

    public void transfer(Client client) {
        this.transfer(client, null, false);
    }

    public void transfer(Client client, JsonObject extra, boolean needDisconnect) {
        PlayerTransferEvent ev;
        this.server.getPluginManager().callEvent(ev = new PlayerTransferEvent(this, client, needDisconnect));
        if (!ev.isCancelled()) {
            if (this.client != null && needDisconnect) {
                PlayerLogoutPacket pk = new PlayerLogoutPacket();
                pk.uuid = this.uuid;
                pk.reason = "Player has been transferred";
                this.client.sendDataPacket(pk);
                this.client.removePlayer(this);
                //this.removeAllPlayers();
            }
            this.client = ev.getTargetClient();
            this.client.addPlayer(this);
            PlayerLoginPacket pk = new PlayerLoginPacket();
            pk.uuid = this.uuid;
            pk.address = this.getIp();
            pk.port = this.getPort();
            pk.isFirstTime = this.isFirstTimeLogin;
            pk.cachedLoginPacket = this.cachedLoginPacket;
            pk.protocol = this.getProtocol();
            if (extra != null) {
                pk.extra = extra;
            } else {
                pk.extra.addProperty("username", this.getName());
                pk.extra.addProperty("xuid", this.xuid);
                pk.extra.addProperty("netease", this.isNeteaseClient());
            }
            if (this.hideName != null) {
                pk.extra.addProperty("hideName", this.hideName);
            }

            this.client.sendDataPacket(pk);

            this.isFirstTimeLogin = false;

            this.server.getLogger().info(this.name + " has been transferred to " + this.client.getDescription());
        }
    }

    public void sendDataPacket(DataPacket pk) {
        this.interfaz.putPacket(this, pk, false, true);
    }

    @Deprecated
    public void sendDataPacket(DataPacket pk, boolean direct) {
        this.sendDataPacket(pk);
    }

    @Deprecated
    public void sendDataPacket(DataPacket pk, boolean direct, boolean needACK) {
        this.sendDataPacket(pk);
    }

    public int getPing() {
        return this.interfaz.getNetworkLatency(this);
    }

    public void close() {
        this.close("Generic Reason");
    }

    public void close(String reason) {
        this.close(reason, true);
    }

    public void close(String reason, boolean notify) {
        if (!this.closed) {
            if (notify && reason.length() > 0) {
                DisconnectPacket pk = new DisconnectPacket();
                pk.hideDisconnectionScreen = false;
                pk.message = reason;
                this.sendDataPacket(pk);
            }

            this.server.getPluginManager().callEvent(new PlayerLogoutEvent(this));
            this.closed = true;

            if (this.client != null) {
                PlayerLogoutPacket pk = new PlayerLogoutPacket();
                pk.uuid = this.uuid;
                pk.reason = reason;
                this.client.sendDataPacket(pk);
                this.client.removePlayer(this);
            }

            this.server.getLogger().info(this.getServer().getLanguage().translateString("nemisys.player.logOut", new String[]{
                    TextFormat.AQUA + this.getName() + TextFormat.WHITE,
                    this.getIp(),
                    String.valueOf(this.getPort()),
                    this.getServer().getLanguage().translateString(reason)
            }));

            Server.getInstance().getScheduler().scheduleDelayedTask(() -> this.interfaz.close(this, notify ? reason : ""), 1);
            this.getServer().removePlayer(this);
        }
    }

    public boolean isNeteaseClient() {
        return neteaseClient;
    }

    public void sendMessage(String message) {
        TextPacket pk = new TextPacket();
        pk.type = TextPacket.TYPE_RAW;
        pk.message = message;

        this.sendDataPacket(pk);
    }

    public void sendPopup(String message) {
        this.sendPopup(message, "");
    }

    public void sendPopup(String message, String subtitle) {
        TextPacket pk = new TextPacket();
        pk.type = TextPacket.TYPE_POPUP;
        pk.message = message;
        pk.primaryName = subtitle;
        this.sendDataPacket(pk);
    }

    public int rawHashCode() {
        return super.hashCode();
    }

    public int getProtocol() {
        return protocol;
    }

    public long getRandomClientId() {
        return randomClientId;
    }

    public Skin getSkin() {
        return this.skin;
    }

    public Client getClient() {
        return client;
    }

    public LoginChainData getLoginChainData() {
        return loginChainData;
    }

    protected void setupNetworkEncryption() {
        if (this.interfaz instanceof RakNetInterface) {
            ((RakNetInterface) this.interfaz).enableEncryption(this);
        }
    }
}
