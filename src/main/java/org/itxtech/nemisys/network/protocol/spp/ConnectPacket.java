package org.itxtech.nemisys.network.protocol.spp;

import com.google.gson.JsonObject;
import org.itxtech.nemisys.utils.JsonUtil;

/**
 * Created by boybook on 16/6/24.
 */
public class ConnectPacket extends SynapseDataPacket {

    public static final int NETWORK_ID = SynapseInfo.CONNECT_PACKET;

    public int protocol = SynapseInfo.CURRENT_PROTOCOL;
    public int maxPlayers;
    public boolean isMainServer;
    public String description;
    public String password;
    public JsonObject metadata = new JsonObject();

    @Override
    public byte pid() {
        return NETWORK_ID;
    }

    @Override
    public void encode() {
        this.reset();
        this.putInt(this.protocol);
        this.putVarInt(this.maxPlayers);
        this.putBoolean(this.isMainServer);
        this.putString(this.description);
        this.putString(this.password);
        this.putString(JsonUtil.GSON.toJson(this.metadata));
    }

    @Override
    public void decode() {
        this.protocol = this.getInt();
        this.maxPlayers = this.getVarInt();
        this.isMainServer = this.getBoolean();
        this.description = this.getString();
        this.password = this.getString();
        this.metadata = JsonUtil.GSON.fromJson(this.getString(), JsonObject.class);
    }
}
