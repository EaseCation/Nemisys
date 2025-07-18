package org.itxtech.nemisys.utils;

import lombok.extern.log4j.Log4j2;
import org.itxtech.nemisys.Server;

import java.io.IOException;

@Log4j2
public abstract class Zlib {
    private static final ZlibProvider[] providers;
    private static ZlibProvider provider;

    static {
        providers = new ZlibProvider[3];
        providers[2] = new ZlibThreadLocal();
        provider = providers[2];
    }

    public static void setProvider(int providerIndex) {
        log.info("Selected Zlib Provider: " + providerIndex + " (" + provider.getClass().getCanonicalName() + ")");
        switch (providerIndex) {
            case 0:
                if (providers[providerIndex] == null)
                    providers[providerIndex] = new ZlibOriginal();
                break;
            case 1:
                if (providers[providerIndex] == null)
                    providers[providerIndex] = new ZlibSingleThreadLowMem();
                break;
            case 2:
                if (providers[providerIndex] == null)
                    providers[providerIndex] = new ZlibThreadLocal();
                break;
            default:
                throw new UnsupportedOperationException("Invalid provider: " + providerIndex);
        }
        if (providerIndex != 2) {
            log.warn(" - This Zlib will negatively affect performance");
        }
        provider = providers[providerIndex];
    }

    public static byte[] deflate(byte[] data) throws Exception {
        return deflate(data, Server.getInstance().getNetworkCompressionLevel());
    }

    public static byte[] deflate(byte[] data, int level) throws IOException {
        return provider.deflate(data, level);
    }

    public static byte[] deflate(byte[][] data, int level) throws Exception {
        return provider.deflate(data, level);
    }

    public static byte[] inflate(byte[] data) throws IOException {
        return inflate(data, -1);
    }

    public static byte[] inflate(byte[] data, int maxSize) throws IOException {
        return provider.inflate(data, maxSize);
    }
}
