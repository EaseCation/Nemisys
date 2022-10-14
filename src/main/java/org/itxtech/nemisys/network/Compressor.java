package org.itxtech.nemisys.network;

import org.itxtech.nemisys.utils.Zlib;
import org.xerial.snappy.Snappy;

import java.io.IOException;
import java.util.zip.DataFormatException;

public enum Compressor {
    NONE {
        @Override
        public byte[] compress(byte[] data, int level) {
            return data;
        }

        @Override
        public byte[] decompress(byte[] data) {
            return data;
        }
    },
    ZLIB {
        @Override
        public byte[] compress(byte[] data, int level) throws IOException {
            return Zlib.deflate(data, level);
        }

        @Override
        public byte[] decompress(byte[] data) throws IOException {
            return Zlib.inflate(data, 2 * 1024 * 1024); // Max 2MB
        }
    },
    ZLIB_RAW {
        @Override
        public byte[] compress(byte[] data, int level) throws IOException {
            return Network.deflateRaw(data, level);
        }

        @Override
        public byte[] decompress(byte[] data) throws IOException, DataFormatException {
            return Network.inflateRaw(data);
        }
    },
    ZLIB_UNKNOWN {
        @Override
        public byte[] compress(byte[] data, int level) throws IOException {
            return ZLIB_RAW.compress(data, level);
        }

        @Override
        public byte[] decompress(byte[] data) {
            try {
                return ZLIB_RAW.decompress(data);
            } catch (Exception e) {
                try {
                    return ZLIB.decompress(data);
                } catch (Exception e0) {
                    return EMPTY;
                }
            }
        }
    },
    SNAPPY {
        @Override
        public byte[] compress(byte[] data, int level) throws IOException {
            return Snappy.compress(data);
        }

        @Override
        public byte[] decompress(byte[] data) throws IOException {
            return Snappy.uncompress(data);
        }
    };

    private static final byte[] EMPTY = new byte[0];

    public abstract byte[] compress(byte[] data, int level) throws IOException;

    public abstract byte[] decompress(byte[] data) throws IOException, DataFormatException;
}
