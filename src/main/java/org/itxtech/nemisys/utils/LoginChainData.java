package org.itxtech.nemisys.utils;

import java.util.UUID;

/**
 * @author CreeperFace
 */
public interface LoginChainData {
    int AUTHENTICATION_OFFER_INVALID = 0;
    int AUTHENTICATION_OFFER_MOJANG = 1;
    int AUTHENTICATION_OFFER_NETEASE = 2;
    int AUTHENTICATION_OFFER_EASECATION = 3;

    int getAuthenticationOffer();

    String getUsername();

    UUID getClientUUID();

    String getIdentityPublicKey();

    String getNetEaseUID();

    String getNetEaseSid();

    String getNetEaseDataVersion();

    String getNetEasePlatform();

    String getNetEaseClientOsName();

    String getNetEaseClientBit();

    String getNetEaseClientEngineVersion();

    String getNetEaseClientPatchVersion();

    String getNetEaseEnv();

    String getNetEaseGameType();

    long getClientId();

    String getServerAddress();

    String getDeviceId();

    String getDeviceModel();

    int getDeviceOS();

    String getGameVersion();

    int getGuiScale();

    String getLanguageCode();

    String getXUID();

    int getCurrentInputMode();

    int getDefaultInputMode();

    int getUIProfile();

    String getPlatformOfflineId();

    String getPlatformOnlineId();

    boolean isEditorMode();

    boolean isSupportClientChunkGeneration();

    int getPlatformType();

    int getMemoryTier();

    int getMaxViewDistance();

    int getGraphicsMode();

    boolean isNetEaseReconnect();

    String getNetEaseSkinIID();

    int getNetEaseGrowthLevel();

    String getNetEaseBloomData();

    int getAuthenticationType();

    String getToken();

    String getCertificate();

    String[] getOriginChainArr();

    String getSubject();

    String getPlayFabId();

    Integer getPfcd();

    String getIpt();

    String getTitleId();

    String getSandboxId();

    default String getViaProxyAuthToken() {
        return null;
    }
}
