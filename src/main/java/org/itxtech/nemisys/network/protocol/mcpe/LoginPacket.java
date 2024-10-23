package org.itxtech.nemisys.network.protocol.mcpe;

import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.netease.mc.authlib.Profile;
import com.netease.mc.authlib.TokenChain;
import lombok.ToString;
import lombok.extern.log4j.Log4j2;
import org.itxtech.nemisys.Server;
import org.itxtech.nemisys.utils.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Created by on 15-10-13.
 */
@Log4j2
@ToString
public class LoginPacket extends DataPacket {

    public static final int NETWORK_ID = ProtocolInfo.LOGIN_PACKET;

    public String username;
    public int protocol;
    public UUID clientUUID;
    public String xuid;
    public String identityPublicKey;

    public transient byte[] cacheBuffer;
    public LoginChainData decodedLoginChainData;
    public boolean netEaseClient;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    @Override
    public boolean canBeSentBeforeLogin() {
        return true;
    }

    @Override
    public void decode() {
        int start = this.getOffset();
        this.cacheBuffer = this.getBuffer();
        this.protocol = this.getInt();

        if (start == 1 && this.protocol <= 113) {
            getByte();
        }

        this.setBuffer(this.getByteArray(), 0);

        decodeChainData();

        tryDecodeLoginChainData();
    }

    public void tryDecodeLoginChainData() {
        try {
            byte[] buffer = getBuffer();

            decodedLoginChainData = ClientChainDataNetEase.of(buffer);
            if (decodedLoginChainData.getClientUUID() != null) { // 网易认证通过！
                this.netEaseClient = true;
                log.debug("[Login] {} {}中国版验证通过！{}", username, TextFormat.RED, protocol);
                return;
            }

            try { // 国际版普通认证
                log.debug("[Login] {} {}正在解析为国际版！{}", username, TextFormat.GREEN, protocol);
                decodedLoginChainData = ClientChainData.of(buffer);
            } catch (Exception e) {
                log.debug("[Login] {} {}解析时出现问题，采用紧急解析方案！", username, TextFormat.YELLOW, e);
                decodedLoginChainData = ClientChainDataUrgency.of(buffer);
            }
        } catch (Exception e) {
            decodedLoginChainData = null;
            if (log.isDebugEnabled()) {
                log.throwing(e);
            }
        }
    }

    public int getProtocol() {
        return protocol;
    }

    private void decodeChainData() {
        Map<String, List<String>> map = JsonUtil.GSON.fromJson(new String(this.get(getLInt()), StandardCharsets.UTF_8),
                    new TypeToken<Map<String, List<String>>>() {
                    }.getType());
        try {
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
        Map<String, List<String>> map = JsonUtil.GSON.fromJson(new String(this.get(this.getLInt()), StandardCharsets.UTF_8),
                new TypeToken<Map<String, List<String>>>() {
                }.getType());
        List<String> chains = map.get("chain");
        if (chains == null) {
            return;
        }
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
        try {
            Profile profile = TokenChain.check(chainArr);
            this.xuid = profile.XUID;
            this.clientUUID = profile.identity;
            this.username = profile.displayName;
            this.identityPublicKey = profile.clientPubKey;
        } catch (Exception e) {
            Server.getInstance().getLogger().logException(e);
            // TODO: handle exception,认证失败
            this.clientUUID = null;//若认证失败，则clientUUID为null。
        }
    }

    private JsonObject decodeToken(String token) {
        String[] base = token.split("\\.", 4);
        if (base.length < 2) return null;
        String forDecode = base[1];
        byte[] decode;
    	try {
        	decode = Base64.getUrlDecoder().decode(forDecode);
        } catch(IllegalArgumentException e) {
        	decode = Base64.getDecoder().decode(forDecode);
        }

        return JsonUtil.GSON.fromJson(new String(decode, StandardCharsets.UTF_8), JsonObject.class);
    }
}
