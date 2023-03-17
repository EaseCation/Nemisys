package org.itxtech.nemisys.utils;

import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.netease.mc.authlib.Profile;
import com.netease.mc.authlib.TokenChain;
import org.itxtech.nemisys.network.protocol.mcpe.LoginPacket;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * @author CreeperFace
 */
public final class ClientChainDataNetEase implements LoginChainData {

    public static ClientChainDataNetEase of(byte[] buffer) {
        return new ClientChainDataNetEase(buffer);
    }

    public static ClientChainDataNetEase read(LoginPacket pk) {
        return of(pk.getBuffer());
    }

    public String getUsername() {
        return username;
    }

    public UUID getClientUUID() {
        return clientUUID;
    }

    public String getIdentityPublicKey() {
        return identityPublicKey;
    }

    public long getClientId() {
        return clientId;
    }

    public String getServerAddress() {
        return serverAddress;
    }

    public String getDeviceModel() {
        return deviceModel;
    }

    public int getDeviceOS() {
        return deviceOS;
    }

    public String getGameVersion() {
        return gameVersion;
    }

    public int getGuiScale() {
        return guiScale;
    }

    public String getLanguageCode() {
        return languageCode;
    }

    public String getXUID() {
        return xuid;
    }

    public int getCurrentInputMode() {
        return currentInputMode;
    }

    public int getDefaultInputMode() {
        return defaultInputMode;
    }

    public String getADRole() {
        return ADRole;
    }

    public String getTenantId() {
        return tenantId;
    }

    public final static int UI_PROFILE_CLASSIC = 0;
    public final static int UI_PROFILE_POCKET = 1;

    public int getUIProfile() {
        return UIProfile;
    }

    @Override
    public String getCapeData() {
        return null;
    }

    public String getXuid() {
        return xuid;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Override
    ///////////////////////////////////////////////////////////////////////////

    @Override
    public boolean equals(Object obj) {
        return obj instanceof ClientChainDataNetEase && Objects.equals(bs, ((ClientChainDataNetEase) obj).bs);
    }

    @Override
    public int hashCode() {
        return bs.hashCode();
    }

    ///////////////////////////////////////////////////////////////////////////
    // Internal
    ///////////////////////////////////////////////////////////////////////////

    private String username;
    private UUID clientUUID;
    private String xuid;
    private String identityPublicKey;

    private long clientId;
    private String serverAddress;
    private String deviceModel;
    private int deviceOS;
    private String gameVersion;
    private int guiScale;
    private String languageCode;
    private int currentInputMode;
    private int defaultInputMode;
    private String ADRole;
    private String tenantId;

    private int UIProfile;

    private final BinaryStream bs = new BinaryStream();

    private ClientChainDataNetEase(byte[] buffer) {
        bs.setBuffer(buffer, 0);
        //decodeChainData();
        neteaseDecode();
        decodeSkinData();
    }

    //netease解析客户端信息。
    private void neteaseDecode() {
        this.xuid = null;
        this.clientUUID = null;
        this.username = null;
        Map<String, List<String>> map = JsonUtil.GSON.fromJson(new String(bs.get(bs.getLInt()), StandardCharsets.UTF_8),
                new TypeToken<Map<String, List<String>>>() {
                }.getType());
        List<String> chains = map.get("chain");
        if (chains == null) {
            return;
        }
        int chainSize = chains.size();
        if (chainSize < 2) { //最少2个字符串。
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
        try {
            Profile profile = TokenChain.check(chainArr);
            this.xuid = profile.XUID;
            this.clientUUID = profile.identity;
            this.username = profile.displayName;
            this.identityPublicKey = profile.clientPubKey;
        } catch (Exception e) {
            // TODO: handle exception,认证失败
            this.clientUUID = null;//若认证失败，则clientUUID为null。
        }
    }


    private void decodeChainData() {
        Map<String, List<String>> map = JsonUtil.GSON.fromJson(new String(bs.get(bs.getLInt()), StandardCharsets.UTF_8),
                new TypeToken<Map<String, List<String>>>() {
                }.getType());
        List<String> chains = map.get("chain");
        if (chains == null || chains.isEmpty()) {
            return;
        }
        for (String c : chains) {
            JsonObject chainMap = decodeToken(c);
            if (chainMap == null) {
                continue;
            }
            if (chainMap.has("extraData")) {
                JsonObject extra = chainMap.get("extraData").getAsJsonObject();
                if (extra.has("displayName")) this.username = extra.get("displayName").getAsString();
                if (extra.has("identity")) this.clientUUID = UUID.fromString(extra.get("identity").getAsString());
                if (extra.has("XUID")) this.xuid = extra.get("XUID").getAsString();
            }
            if (chainMap.has("identityPublicKey")) {
                this.identityPublicKey = chainMap.get("identityPublicKey").getAsString();
            }
        }
    }

    private void decodeSkinData() {
        JsonObject skinToken = decodeToken(new String(bs.get(bs.getLInt())));
        if(skinToken == null) return;
        if (skinToken.has("ClientRandomId")) this.clientId = skinToken.get("ClientRandomId").getAsLong();
        if (skinToken.has("ServerAddress")) this.serverAddress = skinToken.get("ServerAddress").getAsString();
        if (skinToken.has("DeviceModel")) this.deviceModel = skinToken.get("DeviceModel").getAsString();
        if (skinToken.has("DeviceOS")) this.deviceOS = skinToken.get("DeviceOS").getAsInt();
        if (skinToken.has("GameVersion")) this.gameVersion = skinToken.get("GameVersion").getAsString();
        if (skinToken.has("GuiScale")) this.guiScale = skinToken.get("GuiScale").getAsInt();
        if (skinToken.has("LanguageCode")) this.languageCode = skinToken.get("LanguageCode").getAsString();
        if (skinToken.has("CurrentInputMode")) this.currentInputMode = skinToken.get("CurrentInputMode").getAsInt();
        if (skinToken.has("DefaultInputMode")) this.defaultInputMode = skinToken.get("DefaultInputMode").getAsInt();
        if (skinToken.has("ADRole")) this.ADRole = skinToken.get("ADRole").getAsString();
        if (skinToken.has("TenantId")) this.tenantId = skinToken.get("TenantId").getAsString();
        if (skinToken.has("UIProfile")) this.UIProfile = skinToken.get("UIProfile").getAsInt();
    }

    private JsonObject decodeToken(String token) {
        String[] base = token.split("\\.", 4);
        if (base.length < 2) return null;
        String forDecode = base[1];
        byte[] decode;
        try {
        	decode = Base64.getUrlDecoder().decode(forDecode);
        } catch (IllegalArgumentException e) {
        	decode = Base64.getDecoder().decode(forDecode);
        }
        String json = new String(decode, StandardCharsets.UTF_8);
        //Server.getInstance().getLogger().debug(json);
        return JsonUtil.GSON.fromJson(json, JsonObject.class);
    }

}
