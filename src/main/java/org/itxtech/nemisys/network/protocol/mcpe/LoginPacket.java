package org.itxtech.nemisys.network.protocol.mcpe;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.netease.mc.authlib.Profile;
import com.netease.mc.authlib.TokenChain;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.utils.SerializedImage;
import org.itxtech.nemisys.utils.Skin;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Created by on 15-10-13.
 */
public class LoginPacket extends DataPacket {

    public static final int NETWORK_ID = ProtocolInfo.LOGIN_PACKET;

    public String username;
    public int protocol;
    public UUID clientUUID;
    public long clientId;
    public String xuid;
    public String identityPublicKey;

    public Skin skin;
    public byte[] cacheBuffer;

    @Override
    public byte pid() {
        return NETWORK_ID;
    }

    @Override
    public void decode() {
        int start = this.getOffset();
        this.cacheBuffer = this.getBuffer();
        this.protocol = this.getInt();

        if(start == 1 && this.protocol <= 113) {
            getByte();
        }

        this.setBuffer(this.getByteArray(), 0);

        decodeChainData();
        decodeSkinData();
    }

    @Override
    public void encode() {

    }

    public int getProtocol() {
        return protocol;
    }

    private void decodeChainData() {
        Map<String, List<String>> map = new Gson().fromJson(new String(this.get(getLInt()), StandardCharsets.UTF_8),
                    new TypeToken<Map<String, List<String>>>() {
                    }.getType());
        try {
            if (map.isEmpty() || !map.containsKey("chain") || map.get("chain").isEmpty()) return;
            List<String> chains = map.get("chain");
            for (String c : chains) {
                JsonObject chainMap = decodeToken(c);
                if (chainMap == null) continue;
                if (chainMap.has("extraData")) {
                    JsonObject extra = chainMap.get("extraData").getAsJsonObject();
                    if (extra.has("displayName")) this.username = extra.get("displayName").getAsString();
                    if (extra.has("identity")) this.clientUUID = UUID.fromString(extra.get("identity").getAsString());
                    if (extra.has("XUID")) this.xuid = extra.get("XUID").getAsString();
                }
                if (chainMap.has("identityPublicKey"))
                    this.identityPublicKey = chainMap.get("identityPublicKey").getAsString();
            }
        } catch (Exception e) {
            //Server.getInstance().getLogger().logException(e);
            this.setOffset(0);
            neteaseDecode();
            Server.getInstance().getLogger().warning((this.username != null ? this.username : "") + "解析为中国版");
        }
    }

    //netease解析客户端信息。
    private void neteaseDecode() {
        this.xuid = null;
        this.clientUUID = null;
        this.username = null;
        Map<String, List<String>> map = new Gson().fromJson(new String(this.get(this.getLInt()), StandardCharsets.UTF_8),
                new TypeToken<Map<String, List<String>>>() {
                }.getType());
        if (map.isEmpty() || !map.containsKey("chain") || map.get("chain").isEmpty())
            return;
        List<String> chains = map.get("chain");
        int chainSize = chains.size();
        if (chainSize < 2) {//最少2个字符串。
            Server.getInstance().getLogger().alert("过短 shainSize");
            return;
        }
        String[] chainArr = new String[chainSize - 1];
        Iterator<String> iterator = chains.iterator();
        int index = 0;
        iterator.next();
        while (iterator.hasNext()) {
            chainArr[index] = iterator.next();
            ++index;
        }
        try{
            Profile profile = TokenChain.check(chainArr);
            this.xuid = profile.XUID;
            this.clientUUID = profile.identity;
            this.username = profile.displayName;
            this.identityPublicKey = profile.clientPubKey;
        }catch (Exception e) {
            Server.getInstance().getLogger().logException(e);
            // TODO: handle exception,认证失败
            this.clientUUID = null;//若认证失败，则clientUUID为null。
        }
    }

    private void decodeSkinData() {
        JsonObject skinToken = decodeToken(new String(this.get(this.getLInt())));
        if (skinToken.has("ClientRandomId")) this.clientId = skinToken.get("ClientRandomId").getAsLong();
        String skinId = Skin.MODEL_STEVE;
        byte[] skinData = new byte[0];
        if (skinToken.has("SkinId")) {
            skinId = skinToken.get("SkinId").getAsString();
        }
        skinData = getImage(skinToken, "Skin").data;
        skin = new Skin(skinData, skinId);
    }

    private static SerializedImage getImage(JsonObject token, String name) {
        if (token.has(name + "Data")) {
            byte[] skinImage = Base64.getDecoder().decode(token.get(name + "Data").getAsString());
            if (token.has(name + "ImageHeight") && token.has(name + "ImageWidth")) {
                int width = token.get(name + "ImageWidth").getAsInt();
                int height = token.get(name + "ImageHeight").getAsInt();
                return new SerializedImage(width, height, skinImage);
            } else {
                return SerializedImage.fromLegacy(skinImage);
            }
        }
        return SerializedImage.EMPTY;
    }

    private JsonObject decodeToken(String token) {
        String[] base = token.split("\\.");
        if (base.length < 2) return null;
        String forDecode = base[1];
        byte[] decode = null;
    	try {
        	decode = Base64.getUrlDecoder().decode(forDecode);
        } catch(IllegalArgumentException e) {
        	decode = Base64.getDecoder().decode(forDecode);
        }
        
        return new Gson().fromJson(new String(decode, StandardCharsets.UTF_8), JsonObject.class);
    }

    @Override
    public Skin getSkin() {
        return skin;
    }
}