package org.itxtech.nemisys.utils;

import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.ToString;
import lombok.extern.log4j.Log4j2;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
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
@Log4j2
@ToString
public final class ClientChainData implements LoginChainData {

//    @Deprecated
//    private static final String MOJANG_PUBLIC_KEY_BASE64 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8ELkixyLcwlZryUQcu1TvPOmI2B7vX83ndnWRUaXm74wFfa5f/lwQNTfrLVHa2PmenpGI6JhIMUJaWZrjmMj90NoKNFSNBuKdm8rYiXsfaz3K36x/1U26HpG0ZxK/V1V";
//    private static final PublicKey MOJANG_PUBLIC_KEY;
    private static final String NEW_MOJANG_PUBLIC_KEY_BASE64 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECRXueJeTDqNRRgJi/vlRufByu/2G0i2Ebt6YMar5QX/R0DIIyrJMcUpruK4QveTfJSTp3Shlq4Gk34cD/4GUWwkv0DVuzeuB+tXija7HBxii03NHDbPAD0AKnLr2wdAp";
    private static final PublicKey NEW_MOJANG_PUBLIC_KEY;
    private static final String NETEASE_PUBLIC_KEY_BASE64 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEEsmU+IF/XeAF3yiqJ7Ko36btx6JtdB26wV9Eyw4AYR/nmesznkfXxwQ4B0NkSnGIZccbb2f3nFUYughKSoAcNHx+lQm8F9h9RwhrNgeN907z06LUA2AqWcwqasxyaU0E";
    private static final PublicKey NETEASE_PUBLIC_KEY;
    private static final boolean onlineAuth;

    public final static int AUTHENTICATION_TYPE_FULL = 0;
    public final static int AUTHENTICATION_TYPE_GUEST = 1;
    public final static int AUTHENTICATION_TYPE_SELF_SIGNED = 2;

    public final static int UI_PROFILE_CLASSIC = 0;
    public final static int UI_PROFILE_POCKET = 1;

    public final static int INPUT_MOUSE = 1;
    public final static int INPUT_TOUCH = 2;
    public final static int INPUT_GAME_PAD = 3;
    public final static int INPUT_MOTION_CONTROLLER = 4;

    static {
        boolean notAvailable = false;
/*
        PublicKey key;
        try {
            key = generateKey(MOJANG_PUBLIC_KEY_BASE64);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            key = null;
            notAvailable = true;
            log.warn(e);
        }
        MOJANG_PUBLIC_KEY = key;
*/
        PublicKey keyNew;
        try {
            keyNew = generateKey(NEW_MOJANG_PUBLIC_KEY_BASE64);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            keyNew = null;
            notAvailable = true;
            log.warn(e);
        }
        NEW_MOJANG_PUBLIC_KEY = keyNew;

        PublicKey netease;
        try {
            netease = generateKey(NETEASE_PUBLIC_KEY_BASE64);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            netease = null;
            log.warn(e);
        }
        NETEASE_PUBLIC_KEY = netease;

        onlineAuth = !notAvailable;
    }

    public static ClientChainData of(byte[] buffer, int protocol) {
        return new ClientChainData(buffer, protocol);
    }

    @Override
    public int getAuthenticationOffer() {
        return authenticationOffer;
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
    public String getNetEaseDataVersion() {
        return neteaseDataVersion;
    }

    @Override
    public String getNetEasePlatform() {
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
    public String getNetEaseGameType() {
        return neteaseGameType;
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
    public int getDefaultInputMode() {
        return defaultInputMode;
    }

    @Override
    public int getUIProfile() {
        return uiProfile;
    }

    @Override
    public String getPlatformOfflineId() {
        return platformOfflineId;
    }

    @Override
    public String getPlatformOnlineId() {
        return platformOnlineId;
    }

    @Override
    public boolean isEditorMode() {
        return editorMode;
    }

    @Override
    public boolean isSupportClientChunkGeneration() {
        return supportClientChunkGeneration;
    }

    @Override
    public int getPlatformType() {
        return platformType;
    }

    @Override
    public int getMemoryTier() {
        return memoryTier;
    }

    @Override
    public int getMaxViewDistance() {
        return maxViewDistance;
    }

    @Override
    public int getGraphicsMode() {
        return graphicsMode;
    }

    @Override
    public String getPartyId() {
        return partyId;
    }

    @Override
    public boolean isPartyLeader() {
        return partyLeader;
    }

    @Override
    public boolean isNetEaseReconnect() {
        return neteaseReconnect;
    }

    @Override
    public String getNetEaseSkinIID() {
        return neteaseSkinIID;
    }

    @Override
    public int getNetEaseGrowthLevel() {
        return neteaseGrowthLevel;
    }

    @Override
    public String getNetEaseBloomData() {
        return neteaseBloomData;
    }

    @Override
    public int getAuthenticationType() {
        return authenticationType;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public String getCertificate() {
        return certificate;
    }

    @Override
    public String[] getOriginChainArr() {
        return originChainArr;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public String getPlayFabId() {
        return playFabId;
    }

    @Override
    public Integer getPfcd() {
        return pfcd;
    }

    @Override
    public String getIpt() {
        return ipt;
    }

    @Override
    public String getTitleId() {
        return titleId;
    }

    @Override
    public String getSandboxId() {
        return sandboxId;
    }

    @Override
    public String getViaProxyAuthToken() {
        return viaProxyAuthToken;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Internal
    ///////////////////////////////////////////////////////////////////////////

    private int authenticationOffer = AUTHENTICATION_OFFER_INVALID;

    private String username;
    private UUID clientUUID;
    private String xuid;
    private String identityPublicKey;

    private String neteaseUid;
    private String neteaseSid;
    private String neteaseDataVersion;

    private String neteasePlatform;
    private String neteaseClientOsName;
    private String neteaseEnv;
    private String neteaseClientEngineVersion;
    private String neteaseClientPatchVersion;
    private String neteaseClientBit;
    private String neteaseGameType;

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
    private int uiProfile;
    private String platformOfflineId;
    private String platformOnlineId;
    private boolean editorMode;
    private boolean supportClientChunkGeneration;
    private int platformType;
    private int memoryTier;
    private int maxViewDistance;
    private int graphicsMode;
    private String partyId;
    private boolean partyLeader;

    private boolean neteaseReconnect;
    private String neteaseSkinIID;
    private int neteaseGrowthLevel;
    private String neteaseBloomData;

    private int authenticationType = -1;

    private String token;
    private String certificate;
    private String[] originChainArr;

    private String subject;
    private String playFabId;
    private Integer pfcd;

    private String ipt;
    private String titleId;
    private String sandboxId;

    private String viaProxyAuthToken;

    private transient final BinaryStream bs;

    private ClientChainData(byte[] buffer, int protocol) {
        bs = new BinaryStream(buffer);
        decodeChainData(protocol);
        decodeSkinData();
    }

    private void decodeChainData(int protocol) {
        int size = bs.getLInt();
        String json = new String(bs.get(size), StandardCharsets.UTF_8);
        Map<String, ?> root = JsonUtil.GSON.fromJson(json, new TypeToken<Map<String, ?>>(){}.getType());
        if (root == null || root.isEmpty()) {
            return;
        }

        List<String> chains;
        if (protocol >= 818) {
            Object authenticationType = root.get("AuthenticationType");
            if (!(authenticationType instanceof Number type)) {
                return;
            }
            this.authenticationType = type.intValue();

            Object token = root.get("Token");
            if (!(token instanceof String jwt)) {
                return;
            }
            this.token = jwt;
            if (!jwt.isEmpty()) {
                try {
                    decodeTokenData(jwt, this.authenticationType);
                } catch (ParseException e) {
                    // invalid login data
                    this.clientUUID = null;
                }
                return;
            }

            Object certificate = root.get("Certificate");
            if (!(certificate instanceof String cert)) {
                return;
            }
            this.certificate = cert;

            Map<String, List<String>> map = JsonUtil.GSON.fromJson(cert, new TypeToken<Map<String, List<String>>>(){}.getType());
            if (map == null || map.isEmpty() || (chains = map.get("chain")) == null || chains.isEmpty()) {
                return;
            }
        } else {
            Object chain = root.get("chain");
            if (!(chain instanceof List list) || list.isEmpty()) {
                return;
            }
            chains = (List<String>) chain;
        }

        try {
            decodeCertificateData(chains);
        } catch (Exception e) {
            // invalid login data
            this.clientUUID = null;
        }
    }

    private void decodeCertificateData(List<String> chains) {
        if (onlineAuth) {
            // Validate keys
            try {
                authenticationOffer = verifyChain(chains);
            } catch (Exception ignored) {
            }
        }

        this.originChainArr = chains.toArray(new String[0]);

        for (String chain : chains) {
            JsonObject chainMap = decodeToken(chain);
            if (chainMap == null) {
                continue;
            }

            if (chainMap.has("extraData")) {
                JsonObject extra = chainMap.get("extraData").getAsJsonObject();
                if (extra.has("displayName")) this.username = extra.get("displayName").getAsString();
                if (extra.has("identity")) this.clientUUID = UUID.fromString(extra.get("identity").getAsString());
                if (extra.has("XUID")) this.xuid = extra.get("XUID").getAsString();

                if (extra.has("titleId")) this.titleId = extra.get("titleId").getAsString();
                if (extra.has("sandboxId")) this.sandboxId = extra.get("sandboxId").getAsString();

                if (extra.has("uid")) this.neteaseUid = extra.get("uid").getAsString();
                if (extra.has("netease_sid")) this.neteaseSid = extra.get("netease_sid").getAsString();
                if (extra.has("version")) this.neteaseDataVersion = extra.get("version").getAsString();

                if (extra.has("platform")) this.neteasePlatform = extra.get("platform").getAsString();
                if (extra.has("os_name")) this.neteaseClientOsName = extra.get("os_name").getAsString();
                if (extra.has("env")) this.neteaseEnv = extra.get("env").getAsString();
                if (extra.has("engineVersion")) this.neteaseClientEngineVersion = extra.get("engineVersion").getAsString();
                if (extra.has("patchVersion")) this.neteaseClientPatchVersion = extra.get("patchVersion").getAsString();
                if (extra.has("bit")) this.neteaseClientBit = extra.get("bit").getAsString();
                if (extra.has("game_type")) this.neteaseGameType = extra.get("game_type").getAsString();
            }

            if (chainMap.has("identityPublicKey")) {
                this.identityPublicKey = chainMap.get("identityPublicKey").getAsString();
            }
        }
    }

    private void decodeTokenData(String jwt, int authenticationType) throws ParseException {
        SignedJWT jws = SignedJWT.parse(jwt);
        JWTClaimsSet claims = jws.getJWTClaimsSet();

        this.username = claims.getStringClaim("xname");
        this.xuid = claims.getStringClaim("xid");
        this.identityPublicKey = claims.getStringClaim("cpk");
        if (xuid != null && !xuid.isEmpty()) {
            this.clientUUID = UUID.nameUUIDFromBytes(("pocket-auth-1-xuid:" + xuid).getBytes(StandardCharsets.UTF_8));
        }
        this.playFabId = claims.getStringClaim("mid");
        this.pfcd = claims.getIntegerClaim("pfcd");
        this.subject = claims.getSubject();
        this.ipt = claims.getStringClaim("ipt");
        this.titleId = claims.getStringClaim("tid");

        if (onlineAuth) {
            if (verifyToken(authenticationType, jws)) {
                this.authenticationOffer = AUTHENTICATION_OFFER_MOJANG;
            }
        }
    }

    private void decodeSkinData() {
        int size = bs.getLInt();
        String json = new String(bs.get(size), StandardCharsets.UTF_8);
        JsonObject skinToken = decodeToken(json);
        if (skinToken == null) return;

        if (skinToken.has("ClientRandomId")) this.clientId = skinToken.get("ClientRandomId").getAsLong();
        if (skinToken.has("DeviceId")) this.deviceId = skinToken.get("DeviceId").getAsString();
        if (skinToken.has("ServerAddress")) this.serverAddress = skinToken.get("ServerAddress").getAsString();
        if (skinToken.has("DeviceModel")) this.deviceModel = skinToken.get("DeviceModel").getAsString();
        if (skinToken.has("DeviceOS")) this.deviceOS = skinToken.get("DeviceOS").getAsInt();
        if (skinToken.has("GameVersion")) this.gameVersion = skinToken.get("GameVersion").getAsString();
        if (skinToken.has("GuiScale")) this.guiScale = skinToken.get("GuiScale").getAsInt();
        if (skinToken.has("LanguageCode")) this.languageCode = skinToken.get("LanguageCode").getAsString();
        if (skinToken.has("CurrentInputMode")) this.currentInputMode = skinToken.get("CurrentInputMode").getAsInt();
        if (skinToken.has("DefaultInputMode")) this.defaultInputMode = skinToken.get("DefaultInputMode").getAsInt();
        if (skinToken.has("UIProfile")) this.uiProfile = skinToken.get("UIProfile").getAsInt();
        if (skinToken.has("PlatformOfflineId")) this.platformOfflineId = skinToken.get("PlatformOfflineId").getAsString();
        if (skinToken.has("PlatformOnlineId")) this.platformOnlineId = skinToken.get("PlatformOnlineId").getAsString();
        if (skinToken.has("IsEditorMode")) this.editorMode = skinToken.get("IsEditorMode").getAsBoolean();
        if (skinToken.has("CompatibleWithClientSideChunkGen")) this.supportClientChunkGeneration = skinToken.get("CompatibleWithClientSideChunkGen").getAsBoolean();
        if (skinToken.has("PlatformType")) this.platformType = skinToken.get("PlatformType").getAsInt();
        if (skinToken.has("MemoryTier")) this.memoryTier = skinToken.get("MemoryTier").getAsInt();
        if (skinToken.has("MaxViewDistance")) this.maxViewDistance = skinToken.get("MaxViewDistance").getAsInt();
        if (skinToken.has("GraphicsMode")) this.graphicsMode = skinToken.get("GraphicsMode").getAsInt();
        if (skinToken.has("PartyId")) this.partyId = skinToken.get("PartyId").getAsString();
        if (skinToken.has("IsPartyLeader")) this.partyLeader = skinToken.get("IsPartyLeader").getAsBoolean();

        if (skinToken.has("IsReconnect")) this.neteaseReconnect = skinToken.get("IsReconnect").getAsBoolean();
        if (skinToken.has("SkinIID")) this.neteaseSkinIID = skinToken.get("SkinIID").getAsString();
        if (skinToken.has("GrowthLevel")) this.neteaseGrowthLevel = skinToken.get("GrowthLevel").getAsInt();
        if (skinToken.has("BloomData")) this.neteaseBloomData = skinToken.get("BloomData").getAsString();

        if (skinToken.has("ViaProxyAuthToken")) this.viaProxyAuthToken = skinToken.get("ViaProxyAuthToken").getAsString();
    }

    private JsonObject decodeToken(String token) {
        String[] base = token.split("\\.", 3);
        if (base.length != 3) return null;
        byte[] decode;
        try {
            decode = Base64.getUrlDecoder().decode(base[1]);
        } catch(IllegalArgumentException e) {
            decode = Base64.getDecoder().decode(base[1]);
        }
        String json = new String(decode, StandardCharsets.UTF_8);
        return JsonUtil.GSON.fromJson(json, JsonObject.class);
    }

    private static ECPublicKey generateKey(String base64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }

    private static int verifyChain(List<String> chains) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        ECPublicKey lastKey = null;
        int authKeyVerified = 0;

        Iterator<String> iterator = chains.iterator();
        while (iterator.hasNext()) {
            JWSObject jws = JWSObject.parse(iterator.next());

            URI x5u = jws.getHeader().getX509CertURL();
            if (x5u == null) {
                return AUTHENTICATION_OFFER_INVALID;
            }

            ECPublicKey expectedKey = generateKey(x5u.toString());
            // First key is self-signed
            if (lastKey == null) {
                lastKey = expectedKey;
            } else if (!lastKey.equals(expectedKey)) {
                return AUTHENTICATION_OFFER_INVALID;
            }

            if (!verify(lastKey, jws)) {
                return AUTHENTICATION_OFFER_INVALID;
            }

            if (authKeyVerified != AUTHENTICATION_OFFER_INVALID) {
                return iterator.hasNext() ? AUTHENTICATION_OFFER_INVALID : authKeyVerified;
            }

            if (lastKey.equals(NETEASE_PUBLIC_KEY)) {
                authKeyVerified = AUTHENTICATION_OFFER_NETEASE;
            } else if (lastKey.equals(NEW_MOJANG_PUBLIC_KEY)/* || lastKey.equals(MOJANG_PUBLIC_KEY)*/) {
                authKeyVerified = AUTHENTICATION_OFFER_MOJANG;
            }

            Map<String, Object> payload = jws.getPayload().toJSONObject();

            Object nbf = payload.get("nbf");
            if (!(nbf instanceof Number)) {
                return AUTHENTICATION_OFFER_INVALID;
            }
            if (((Number) nbf).longValue() > now) {
                // premature
                return AUTHENTICATION_OFFER_INVALID;
            }

            Object exp = payload.get("exp");
            if (!(exp instanceof Number)) {
                return AUTHENTICATION_OFFER_INVALID;
            }
            if (((Number) exp).longValue() < now) {
                // expire
                return AUTHENTICATION_OFFER_INVALID;
            }

            Object base64key = payload.get("identityPublicKey");
            if (!(base64key instanceof String)) {
                return AUTHENTICATION_OFFER_INVALID;
            }
            lastKey = generateKey((String) base64key);
        }
        return authKeyVerified;
    }

    private static boolean verify(ECPublicKey key, JWSObject object) throws JOSEException {
        return object.verify(new ECDSAVerifier(key));
    }

    private static boolean verifyToken(int authenticationType, SignedJWT jws) {
        if (authenticationType != AUTHENTICATION_TYPE_FULL /*&& authenticationType != AUTHENTICATION_TYPE_GUEST*/) {
            return false;
        }

        try {
            EncryptionUtils.validateToken(jws);
        } catch (BadJOSEException | JOSEException e) {
            return false;
        }
        return true;
    }
}
