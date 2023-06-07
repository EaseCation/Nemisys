package org.itxtech.nemisys.utils;

import java.util.UUID;

/**
 * @author CreeperFace
 */
public interface LoginChainData {

    String getUsername();

    UUID getClientUUID();

    String getIdentityPublicKey();

    String getNetEaseUID();

    String getNetEaseSid();

    String getNetEasePlatform();

    long getClientId();

    String getServerAddress();

    String getDeviceId();

    String getDeviceModel();

    int getDeviceOS();

    String getGameVersion();

    int getGuiScale();

    String getLanguageCode();

    String getXUID();

    default boolean isXboxAuthed() {
        return true;
    }

    int getCurrentInputMode();

    void setCurrentInputMode(int mode);

    int getDefaultInputMode();

    String getCapeData();

    int getUIProfile();

    String[] getOriginChainArr();
}
