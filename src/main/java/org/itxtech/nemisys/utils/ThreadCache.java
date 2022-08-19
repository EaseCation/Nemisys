package org.itxtech.nemisys.utils;

public class ThreadCache {

    public static final ThreadLocal<FastByteArrayOutputStream> fbaos = ThreadLocal.withInitial(() -> new FastByteArrayOutputStream(1024));
}
