package org.itxtech.nemisys.utils;

public class ThreadCache {

    public static void clean() {
        fbaos.clean();
    }

    public static final IterableThreadLocal<FastByteArrayOutputStream> fbaos = new IterableThreadLocal<FastByteArrayOutputStream>() {
        @Override
        public FastByteArrayOutputStream init() {
            return new FastByteArrayOutputStream(1024);
        }
    };
}
