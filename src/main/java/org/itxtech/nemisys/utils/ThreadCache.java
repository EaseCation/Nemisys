package org.itxtech.nemisys.utils;

import io.netty.util.concurrent.FastThreadLocal;

public class ThreadCache {

    public static final FastThreadLocal<FastByteArrayOutputStream> fbaos = new FastThreadLocal<>() {
        @Override
        protected FastByteArrayOutputStream initialValue() {
            return new FastByteArrayOutputStream(8192);
        }
    };
}
