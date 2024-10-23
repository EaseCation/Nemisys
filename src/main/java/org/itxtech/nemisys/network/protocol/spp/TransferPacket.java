package org.itxtech.nemisys.network.protocol.spp;

import com.google.gson.JsonObject;
import org.itxtech.nemisys.utils.JsonUtil;

import java.util.UUID;

/**
 * Created by boybook on 16/6/24.
 */
public class TransferPacket extends SynapseDataPacket {

    public static final int NETWORK_ID = SynapseInfo.TRANSFER_PACKET;

    public UUID sessionId;
    public String clientHash;
    public JsonObject extra = new JsonObject();

    @Override
    public byte pid() {
        return NETWORK_ID;
    }

    @Override
    public void encode() {
        this.reset();
        this.putUUID(this.sessionId);
        this.putString(this.clientHash);
        this.putString(JsonUtil.GSON.toJson(this.extra));
    }

    @Override
    public void decode() {
        this.sessionId = this.getUUID();
        this.clientHash = this.getString();
        this.extra = JsonUtil.GSON.fromJson(this.getString(), JsonObject.class);
    }
}
