package org.itxtech.nemisys.utils;

import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.netease.mc.authlib.TokenChainEC;
import lombok.ToString;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.network.protocol.mcpe.LoginPacket;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * ClientChainData is a container of chain data sent from clients.
 * <p>
 * Device information such as client UUID, xuid and serverAddress, can be
 * read from instances of this object.
 * <p>
 * To get chain data, you can use player.getLoginChainData() or read(loginPacket)
 * <p>
 * ===============
 * author: boybook
 * Nukkit Project
 * ===============
 */
@ToString
public final class ClientChainDataNetEase implements LoginChainData {

    public static ClientChainDataNetEase of(byte[] buffer, int protocol) {
        return new ClientChainDataNetEase(buffer, protocol);
    }

    public static ClientChainDataNetEase read(LoginPacket pk) {
        return of(pk.getBuffer(), pk.getProtocol());
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public UUID getClientUUID() {
        return clientUUID;
    }

    @Override
    public String getIdentityPublicKey() {
        return identityPublicKey;
    }

    @Override
    public long getClientId() {
        return clientId;
    }

    @Override
    public String getNetEaseUID() {
        return neteaseUid;
    }

    @Override
    public String getNetEaseSid() {
        return neteaseSid;
    }

    @Override
    public String  getNetEasePlatform() {
        return neteasePlatform;
    }

    @Override
    public String getNetEaseClientOsName() {
        return neteaseClientOsName;
    }

    @Override
    public String getNetEaseEnv() {
        return neteaseEnv;
    }

    @Override
    public String getNetEaseClientEngineVersion() {
        return neteaseClientEngineVersion;
    }

    @Override
    public String getNetEaseClientPatchVersion() {
        return neteaseClientPatchVersion;
    }

    @Override
    public String getNetEaseClientBit() {
        return neteaseClientBit;
    }

    @Override
    public String getServerAddress() {
        return serverAddress;
    }

    @Override
    public String getDeviceId() {
        return deviceId;
    }

    @Override
    public String getDeviceModel() {
        return deviceModel;
    }

    @Override
    public int getDeviceOS() {
        return deviceOS;
    }

    @Override
    public String getGameVersion() {
        return gameVersion;
    }

    @Override
    public int getGuiScale() {
        return guiScale;
    }

    @Override
    public String getLanguageCode() {
        return languageCode;
    }

    @Override
    public String getXUID() {
        return xuid;
    }

    @Override
    public int getCurrentInputMode() {
        return currentInputMode;
    }

    @Override
    public void setCurrentInputMode(int mode) {
        this.currentInputMode = mode;
    }

    @Override
    public int getDefaultInputMode() {
        return defaultInputMode;
    }

    @Override
    public String getCapeData() {
        return capeData;
    }

    public final static int UI_PROFILE_CLASSIC = 0;
    public final static int UI_PROFILE_POCKET = 1;

    @Override
    public int getUIProfile() {
        return UIProfile;
    }

    @Override
    public String[] getOriginChainArr() {
        return originChainArr;
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
    private String neteaseUid;
    private String neteaseSid;
    private String neteasePlatform;
    private String neteaseClientOsName;
    private String neteaseEnv;
    private String neteaseClientEngineVersion;
    private String neteaseClientPatchVersion;
    private String neteaseClientBit;

    private long clientId;
    private String serverAddress;
    private String deviceId;
    private String deviceModel;
    private int deviceOS;
    private String gameVersion;
    private int guiScale;
    private String languageCode;
    private int currentInputMode;
    private int defaultInputMode;

    private int UIProfile;

    private String capeData;
    private String[] originChainArr;

    private transient final BinaryStream bs = new BinaryStream();

    private ClientChainDataNetEase(byte[] buffer, int protocol) {
        bs.setBuffer(buffer, 0);
        //decodeChainData();
        neteaseDecode(protocol);
        decodeSkinData();
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
                if (extra.has("uid")) this.neteaseUid = extra.get("uid").getAsString();
                if (extra.has("netease_sid")) this.neteaseSid = extra.get("netease_sid").getAsString();
                if (extra.has("os_name")) this.neteaseClientOsName = extra.get("os_name").getAsString();
                if (extra.has("env")) this.neteaseEnv = extra.get("env").getAsString();
                if (extra.has("engineVersion")) this.neteaseClientEngineVersion = extra.get("engineVersion").getAsString();
                if (extra.has("patchVersion")) this.neteaseClientPatchVersion = extra.get("patchVersion").getAsString();
                if (extra.has("bit")) this.neteaseClientBit = extra.get("bit").getAsString();
            }
            if (chainMap.has("identityPublicKey")) {
                this.identityPublicKey = chainMap.get("identityPublicKey").getAsString();
            }
        }
    }

    //netease解析客户端信息。
    private void neteaseDecode(int protocol) {
        this.xuid = null;
        this.clientUUID = null;
        this.username = null;

        Map<String, ?> root = JsonUtil.GSON.fromJson(new String(bs.get(bs.getLInt()), StandardCharsets.UTF_8),
                new TypeToken<Map<String, ?>>() {
                }.getType());
        if (root.isEmpty()) {
            return;
        }
        List<String> chains;
        if (protocol >= 818) {
            Object authenticationType = root.get("AuthenticationType");
            if (!(authenticationType instanceof Number)) { //integer 0
                return;
            }
            Object token = root.get("Token");
            if (!(token instanceof String)) { //empty ""
                return;
            }
            Object certificate = root.get("Certificate");
            if (!(certificate instanceof String cert)) {
                return;
            }
            Map<String, List<String>> map = JsonUtil.GSON.fromJson(cert, new TypeToken<Map<String, List<String>>>() {
            }.getType());
            if (map.isEmpty() || (chains = map.get("chain")) == null || chains.isEmpty()) {
                return;
            }
        } else {
            Object chain = root.get("chain");
            if (!(chain instanceof List list) || list.isEmpty()) {
                return;
            }
            chains = (List<String>) chain;
        }

        int chainSize = chains.size();
        if (chainSize < 2) { //最少2个字符串。
//            Server.getInstance().getLogger().warning("短chainSize");
            return;
        }
        this.originChainArr = chains.toArray(new String[0]);
        String[] chainArr = new String[chainSize - 1];
        Iterator<String> iterator = chains.iterator();
        int index = 0;
        iterator.next();
        while (iterator.hasNext()) {
            chainArr[index] = iterator.next();
            ++index;
        }
        try {
            JsonObject profile = TokenChainEC.check(chainArr);
            if (profile.has("XUID")) this.xuid = profile.get("XUID").getAsString();
            if (profile.has("identity")) this.clientUUID = UUID.fromString(profile.get("identity").getAsString());
            if (profile.has("displayName")) this.username = profile.get("displayName").getAsString();
            if (profile.has("uid")) this.neteaseUid = profile.get("uid").getAsString();
            if (profile.has("netease_sid")) this.neteaseSid = profile.get("netease_sid").getAsString();
            if (profile.has("platform")) this.neteasePlatform = profile.get("platform").getAsString();
            if (profile.has("clientPubKey")) this.identityPublicKey = profile.get("clientPubKey").getAsString();
            if (profile.has("os_name")) this.neteaseClientOsName = profile.get("os_name").getAsString();
            if (profile.has("env")) this.neteaseEnv = profile.get("env").getAsString();
            if (profile.has("engineVersion")) this.neteaseClientEngineVersion = profile.get("engineVersion").getAsString();
            if (profile.has("patchVersion")) this.neteaseClientPatchVersion = profile.get("patchVersion").getAsString();
            if (profile.has("bit")) this.neteaseClientBit = profile.get("bit").getAsString();
        } catch (Exception e) {
            // TODO: handle exception,认证失败
            //Server.getInstance().getLogger().logException(e);
            this.clientUUID = null;//若认证失败，则clientUUID为null。
        }
    }

    private void decodeSkinData() {
        JsonObject skinToken = decodeToken(new String(bs.get(bs.getLInt())));
        if (skinToken == null) return;
        if (skinToken.has("ClientRandomId")) this.clientId = skinToken.get("ClientRandomId").getAsLong();
        if (skinToken.has("ServerAddress")) this.serverAddress = skinToken.get("ServerAddress").getAsString();
        if (skinToken.has("DeviceId")) this.deviceId = skinToken.get("DeviceId").getAsString();
        if (skinToken.has("DeviceModel")) this.deviceModel = skinToken.get("DeviceModel").getAsString();
        if (skinToken.has("DeviceOS")) this.deviceOS = skinToken.get("DeviceOS").getAsInt();
        if (skinToken.has("GameVersion")) this.gameVersion = skinToken.get("GameVersion").getAsString();
        if (skinToken.has("GuiScale")) this.guiScale = skinToken.get("GuiScale").getAsInt();
        if (skinToken.has("LanguageCode")) this.languageCode = skinToken.get("LanguageCode").getAsString();
        if (skinToken.has("CurrentInputMode")) this.currentInputMode = skinToken.get("CurrentInputMode").getAsInt();
        if (skinToken.has("DefaultInputMode")) this.defaultInputMode = skinToken.get("DefaultInputMode").getAsInt();
        if (skinToken.has("UIProfile")) this.UIProfile = skinToken.get("UIProfile").getAsInt();
        if (skinToken.has("CapeData")) this.capeData = skinToken.get("CapeData").getAsString();
    }

    private JsonObject decodeToken(String token) {
        String[] base = token.split("\\.", 4);
        if (base.length < 2) return null;
        byte[] decode;
        try {
            decode = Base64.getUrlDecoder().decode(base[1]);
        } catch(IllegalArgumentException e) {
            decode = Base64.getDecoder().decode(base[1]);
        }
        String json = new String(decode, StandardCharsets.UTF_8);
        //Server.getInstance().getLogger().debug(json);
        return JsonUtil.GSON.fromJson(json, JsonObject.class);
    }

}
