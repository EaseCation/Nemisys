package org.itxtech.nemisys.network;

public interface NemisysMetrics {
    default void bytesOut(int size) {
    }

    default void packetOut(int packetId, int size) {
    }
}
