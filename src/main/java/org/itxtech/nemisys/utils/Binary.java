package org.itxtech.nemisys.utils;

import java.util.Arrays;
import java.util.UUID;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class Binary {

    public static int signByte(int value) {
        return value << 56 >> 56;
    }

    public static int unsignByte(int value) {
        return value & 0xff;
    }

    public static int signShort(int value) {
        return value << 48 >> 48;
    }

    public int unsignShort(int value) {
        return value & 0xffff;
    }

    public static int signInt(int value) {
        return value << 32 >> 32;
    }

    public static int unsignInt(int value) {
        return value;
    }

    //Triad: {0x00,0x00,0x01}<=>1
    public static int readTriad(byte[] bytes) {
        return ((bytes[0] & 0xff) << 16) |
                ((bytes[1] & 0xff) << 8) |
                (bytes[2] & 0xff);
    }

    public static int readTriad(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 16) |
                ((bytes[1 + offset] & 0xff) << 8) |
                (bytes[2 + offset] & 0xff);
    }

    public static byte[] writeTriad(int value) {
        return new byte[]{
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value
        };
    }

    public static void writeTriad(int value, byte[] bytes, int offset) {
        bytes[offset] = (byte) (value >> 16);
        bytes[1 + offset] = (byte) (value >> 8);
        bytes[2 + offset] = (byte) value;
    }

    //LTriad: {0x01,0x00,0x00}<=>1
    public static int readLTriad(byte[] bytes) {
        return ((bytes[2] & 0xff) << 24) |
                ((bytes[1] & 0xff) << 16) |
                ((bytes[0] & 0xff) << 8);
    }

    public static int readLTriad(byte[] bytes, int offset) {
        return ((bytes[2 + offset] & 0xff) << 24) |
                ((bytes[1 + offset] & 0xff) << 16) |
                ((bytes[offset] & 0xff) << 8);
    }

    public static byte[] writeLTriad(int value) {
        return new byte[]{
                (byte) value,
                (byte) (value >> 8),
                (byte) (value >> 16)
        };
    }

    public static void writeLTriad(int value, byte[] bytes, int offset) {
        bytes[offset] = (byte) value;
        bytes[1 + offset] = (byte) (value >> 8);
        bytes[2 + offset] = (byte) (value >> 16);
    }

    public static UUID readUUID(byte[] bytes) {
        return new UUID(readLLong(bytes), readLLong(bytes, 8));
    }

    public static UUID readUUID(byte[] bytes, int offset) {
        return new UUID(readLLong(bytes, offset), readLLong(bytes, 8 + offset));
    }

    public static byte[] writeUUID(UUID uuid) {
        return appendBytes(writeLLong(uuid.getMostSignificantBits()), writeLLong(uuid.getLeastSignificantBits()));
    }

    public static void writeUUID(UUID uuid, byte[] bytes, int offset) {
        writeLLong(uuid.getMostSignificantBits(), bytes, offset);
        writeLLong(uuid.getLeastSignificantBits(), bytes, 8 + offset);
    }

    public static boolean readBool(byte b) {
        return b == 0;
    }

    public static byte writeBool(boolean b) {
        return (byte) (b ? 0x01 : 0x00);
    }

    public static int readSignedByte(byte b) {
        return b & 0xFF;
    }

    public static byte writeByte(byte b) {
        return b;
    }

    public static int readShort(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
    }

    public static int readShort(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) << 8 |
                (bytes[1 + offset] & 0xff);
    }

    public static short readSignedShort(byte[] bytes) {
        return (short) ((bytes[0] << 8) |
                (bytes[1] & 0xff));
    }

    public static short readSignedShort(byte[] bytes, int offset) {
        return (short) ((bytes[offset] << 8) |
                (bytes[1 + offset] & 0xff));
    }

    public static byte[] writeShort(int s) {
        return new byte[]{
                (byte) (s >> 8),
                (byte) s
        };
    }

    public static void writeShort(int s, byte[] bytes, int offset) {
        bytes[offset] = (byte) (s >> 8);
        bytes[1 + offset] = (byte) s;
    }

    public static int readLShort(byte[] bytes) {
        return ((bytes[1] & 0xFF) << 8) | (bytes[0] & 0xFF);
    }

    public static int readLShort(byte[] bytes, int offset) {
        return ((bytes[1 + offset] & 0xff) << 8) |
                (bytes[offset] & 0xff);
    }

    public static short readSignedLShort(byte[] bytes) {
        return (short) ((bytes[1] << 8) |
                (bytes[0] & 0xff));
    }

    public static short readSignedLShort(byte[] bytes, int offset) {
        return (short) ((bytes[1 + offset] << 8) |
                (bytes[offset] & 0xff));
    }

    public static byte[] writeLShort(int s) {
        return new byte[]{
                (byte) s,
                (byte) (s >> 8)
        };
    }

    public static void writeLShort(int s, byte[] bytes, int offset) {
        bytes[offset] = (byte) s;
        bytes[1 + offset] = (byte) (s >> 8);
    }

    public static int readInt(byte[] bytes) {
        return bytes[0] << 24 |
                (bytes[1] & 0xff) << 16 |
                (bytes[2] & 0xff) << 8 |
                (bytes[3] & 0xff);
    }

    public static int readInt(byte[] bytes, int offset) {
        return bytes[offset] << 24 |
                (bytes[1 + offset] & 0xff) << 16 |
                (bytes[2 + offset] & 0xff) << 8 |
                (bytes[3 + offset] & 0xff);
    }

    public static byte[] writeInt(int i) {
        return new byte[]{
                (byte) (i >> 24),
                (byte) (i >> 16),
                (byte) (i >> 8),
                (byte) i
        };
    }

    public static void writeInt(int i, byte[] bytes, int offset) {
        bytes[offset] = (byte) (i >> 24);
        bytes[1 + offset] = (byte) (i >> 16);
        bytes[2 + offset] = (byte) (i >> 8);
        bytes[3 + offset] = (byte) i;
    }

    public static int readLInt(byte[] bytes) {
        return (bytes[3] << 24) |
                ((bytes[2] & 0xff) << 16) |
                ((bytes[1] & 0xff) << 8) |
                (bytes[0] & 0xff);
    }

    public static int readLInt(byte[] bytes, int offset) {
        return (bytes[3 + offset] << 24) |
                ((bytes[2 + offset] & 0xff) << 16) |
                ((bytes[1 + offset] & 0xff) << 8) |
                (bytes[offset] & 0xff);
    }

    public static byte[] writeLInt(int i) {
        return new byte[]{
                (byte) i,
                (byte) (i >> 8),
                (byte) (i >> 16),
                (byte) (i >> 24)
        };
    }

    public static void writeLInt(int i, byte[] bytes, int offset) {
        bytes[offset] = (byte) i;
        bytes[1 + offset] = (byte) (i >> 8);
        bytes[2 + offset] = (byte) (i >> 16);
        bytes[3 + offset] = (byte) (i >> 24);
    }

    public static float readFloat(byte[] bytes) {
        return Float.intBitsToFloat(readInt(bytes));
    }

    public static float readFloat(byte[] bytes, int offset) {
        return Float.intBitsToFloat(readInt(bytes, offset));
    }

    public static byte[] writeFloat(float f) {
        return writeInt(Float.floatToIntBits(f));
    }

    public static void writeFloat(float f, byte[] bytes, int offset) {
        writeInt(Float.floatToIntBits(f), bytes, offset);
    }

    public static float readLFloat(byte[] bytes) {
        return Float.intBitsToFloat(readLInt(bytes));
    }

    public static float readLFloat(byte[] bytes, int offset) {
        return Float.intBitsToFloat(readLInt(bytes, offset));
    }

    public static byte[] writeLFloat(float f) {
        return writeLInt(Float.floatToIntBits(f));
    }

    public static void writeLFloat(float f, byte[] bytes, int offset) {
        writeLInt(Float.floatToIntBits(f), bytes, offset);
    }

    public static double readDouble(byte[] bytes) {
        return Double.longBitsToDouble(readLong(bytes));
    }

    public static double readDouble(byte[] bytes, int offset) {
        return Double.longBitsToDouble(readLong(bytes, offset));
    }

    public static byte[] writeDouble(double d) {
        return writeLong(Double.doubleToLongBits(d));
    }

    public static void writeDouble(double d, byte[] bytes, int offset) {
        writeLong(Double.doubleToLongBits(d), bytes, offset);
    }

    public static double readLDouble(byte[] bytes) {
        return Double.longBitsToDouble(readLLong(bytes));
    }

    public static double readLDouble(byte[] bytes, int offset) {
        return Double.longBitsToDouble(readLLong(bytes, offset));
    }

    public static byte[] writeLDouble(double d) {
        return writeLLong(Double.doubleToLongBits(d));
    }

    public static void writeLDouble(double d, byte[] bytes, int offset) {
        writeLLong(Double.doubleToLongBits(d), bytes, offset);
    }

    public static long readLong(byte[] bytes) {
        return ((long) bytes[0] << 56) |
                ((long) (bytes[1] & 0xFF) << 48) |
                ((long) (bytes[2] & 0xFF) << 40) |
                ((long) (bytes[3] & 0xFF) << 32) |
                ((long) (bytes[4] & 0xFF) << 24) |
                ((bytes[5] & 0xFF) << 16) |
                ((bytes[6] & 0xFF) << 8) |
                ((bytes[7] & 0xFF));
    }

    public static long readLong(byte[] bytes, int offset) {
        return ((long) bytes[offset] << 56) |
                ((long) (bytes[1 + offset] & 0xff) << 48) |
                ((long) (bytes[2 + offset] & 0xff) << 40) |
                ((long) (bytes[3 + offset] & 0xff) << 32) |
                ((long) (bytes[4 + offset] & 0xff) << 24) |
                ((bytes[5 + offset] & 0xff) << 16) |
                ((bytes[6 + offset] & 0xff) << 8) |
                ((bytes[7 + offset] & 0xff));
    }

    public static byte[] writeLong(long l) {
        return new byte[]{
                (byte) (l >> 56),
                (byte) (l >> 48),
                (byte) (l >> 40),
                (byte) (l >> 32),
                (byte) (l >> 24),
                (byte) (l >> 16),
                (byte) (l >> 8),
                (byte) l
        };
    }

    public static void writeLong(long l, byte[] bytes, int offset) {
        bytes[offset] = (byte) (l >> 56);
        bytes[1 + offset] = (byte) (l >> 48);
        bytes[2 + offset] = (byte) (l >> 40);
        bytes[3 + offset] = (byte) (l >> 32);
        bytes[4 + offset] = (byte) (l >> 24);
        bytes[5 + offset] = (byte) (l >> 16);
        bytes[6 + offset] = (byte) (l >> 8);
        bytes[7 + offset] = (byte) l;
    }

    public static long readLLong(byte[] bytes) {
        return ((long) bytes[7] << 56) |
                ((long) (bytes[6] & 0xFF) << 48) |
                ((long) (bytes[5] & 0xFF) << 40) |
                ((long) (bytes[4] & 0xFF) << 32) |
                ((long) (bytes[3] & 0xFF) << 24) |
                ((bytes[2] & 0xFF) << 16) |
                ((bytes[1] & 0xFF) << 8) |
                ((bytes[0] & 0xFF));
    }

    public static long readLLong(byte[] bytes, int offset) {
        return ((long) bytes[7 + offset] << 56) |
                ((long) (bytes[6 + offset] & 0xff) << 48) |
                ((long) (bytes[5 + offset] & 0xff) << 40) |
                ((long) (bytes[4 + offset] & 0xff) << 32) |
                ((long) (bytes[3 + offset] & 0xff) << 24) |
                ((bytes[2 + offset] & 0xff) << 16) |
                ((bytes[1 + offset] & 0xff) << 8) |
                ((bytes[offset] & 0xff));
    }

    public static byte[] writeLLong(long l) {
        return new byte[]{
                (byte) l,
                (byte) (l >> 8),
                (byte) (l >> 16),
                (byte) (l >> 24),
                (byte) (l >> 32),
                (byte) (l >> 40),
                (byte) (l >> 48),
                (byte) (l >> 56),
        };
    }

    public static void writeLLong(long l, byte[] bytes, int offset) {
        bytes[offset] = (byte) l;
        bytes[1 + offset] = (byte) (l >> 8);
        bytes[2 + offset] = (byte) (l >> 16);
        bytes[3 + offset] = (byte) (l >> 24);
        bytes[4 + offset] = (byte) (l >> 32);
        bytes[5 + offset] = (byte) (l >> 40);
        bytes[6 + offset] = (byte) (l >> 48);
        bytes[7 + offset] = (byte) (l >> 56);
    }

    public static byte[] writeVarInt(int v) {
        BinaryStream stream = new BinaryStream(5);
        stream.putVarInt(v);
        return stream.getBuffer();
    }

    public static byte[] writeUnsignedVarInt(long v) {
        BinaryStream stream = new BinaryStream(5);
        stream.putUnsignedVarInt(v);
        return stream.getBuffer();
    }

    public static byte[] writeVarLong(long v) {
        BinaryStream stream = new BinaryStream(10);
        stream.putVarLong(v);
        return stream.getBuffer();
    }

    public static byte[] writeUnsignedVarLong(long v) {
        BinaryStream stream = new BinaryStream(10);
        stream.putUnsignedVarLong(v);
        return stream.getBuffer();
    }

    public static byte[] reserveBytes(byte[] bytes) {
        byte[] newBytes = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            newBytes[bytes.length - 1 - i] = bytes[i];
        }
        return newBytes;
    }

    public static String bytesToHexString(byte[] src) {
        return bytesToHexString(src, false);
    }

    public static String bytesToHexString(byte[] src, boolean blank) {
        StringBuilder stringBuilder = new StringBuilder();
        if (src == null || src.length == 0) {
            return null;
        }

        for (byte b : src) {
            if (!stringBuilder.isEmpty() && blank) {
                stringBuilder.append(" ");
            }
            int v = b & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString().toUpperCase();
    }

    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.isEmpty()) {
            return null;
        }
        String str = "0123456789ABCDEF";
        hexString = hexString.toUpperCase().replace(" ", "");
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (((byte) str.indexOf(hexChars[pos]) << 4) | ((byte) str.indexOf(hexChars[pos + 1])));
        }
        return d;
    }

    public static byte[] subBytes(byte[] bytes, int start, int length) {
        int len = Math.min(bytes.length, start + length);
        return Arrays.copyOfRange(bytes, start, len);
    }

    public static byte[] subBytes(byte[] bytes, int start) {
        return subBytes(bytes, start, bytes.length - start);
    }

    public static byte[][] splitBytes(byte[] bytes, int chunkSize) {
        byte[][] splits = new byte[(bytes.length + chunkSize - 1) / chunkSize][chunkSize];
        int chunks = 0;

        for (int i = 0; i < bytes.length; i += chunkSize) {
            if ((bytes.length - i) > chunkSize) {
                splits[chunks] = Arrays.copyOfRange(bytes, i, i + chunkSize);
            } else {
                splits[chunks] = Arrays.copyOfRange(bytes, i, bytes.length);
            }
            chunks++;
        }

        return splits;
    }

    public static byte[] appendBytes(byte[][] bytes) {
        int length = 0;
        for (byte[] b : bytes) {
            length += b.length;
        }

        byte[] appendedBytes = new byte[length];
        int index = 0;
        for (byte[] b : bytes) {
            System.arraycopy(b, 0, appendedBytes, index, b.length);
            index += b.length;
        }
        return appendedBytes;
    }

    public static byte[] appendBytes(byte byte1, byte[]... bytes2) {
        int length = 1;
        for (byte[] bytes : bytes2) {
            length += bytes.length;
        }

        byte[] appendedBytes = new byte[length];
        appendedBytes[0] = byte1;
        int index = 1;

        for (byte[] b : bytes2) {
            System.arraycopy(b, 0, appendedBytes, index, b.length);
            index += b.length;
        }
        return appendedBytes;
    }

    public static byte[] appendBytes(byte[] bytes1, byte[]... bytes2) {
        int length = bytes1.length;
        for (byte[] bytes : bytes2) {
            length += bytes.length;
        }

        byte[] appendedBytes = new byte[length];
        System.arraycopy(bytes1, 0, appendedBytes, 0, bytes1.length);
        int index = bytes1.length;

        for (byte[] b : bytes2) {
            System.arraycopy(b, 0, appendedBytes, index, b.length);
            index += b.length;
        }
        return appendedBytes;
    }
}
