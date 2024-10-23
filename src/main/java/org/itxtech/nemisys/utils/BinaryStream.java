package org.itxtech.nemisys.utils;

import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class BinaryStream {

    public int offset;
    private byte[] buffer;
    private int count;

    private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

    public BinaryStream() {
        this.buffer = new byte[32];
        this.offset = 0;
        this.count = 0;
    }

    public BinaryStream(int initialCapacity) {
        this.buffer = new byte[initialCapacity];
        this.offset = 0;
        this.count = 0;
    }

    public BinaryStream(byte[] buffer) {
        this(buffer, 0);
    }

    public BinaryStream(byte[] buffer, int offset) {
        this.buffer = buffer;
        this.offset = offset;
        this.count = buffer.length;
    }

    public void reuse() {
        this.offset = 0;
        this.count = 0;
    }

    public void reset() {
        this.buffer = new byte[32];
        this.offset = 0;
        this.count = 0;
    }

    public final void superReset() {
        this.buffer = new byte[32];
        this.offset = 0;
        this.count = 0;
    }

    public void setBuffer(byte[] buffer) {
        this.buffer = buffer;
        this.count = buffer == null ? -1 : buffer.length;
    }

    public void setBuffer(byte[] buffer, int offset) {
        this.setBuffer(buffer);
        this.setOffset(offset);
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public byte[] getBuffer() {
        return Arrays.copyOf(buffer, count);
    }

    public byte[] getBuffer(int from) {
        return Arrays.copyOfRange(buffer, from, count);
    }

    public byte[] getBuffer(int from, int to) {
        return Arrays.copyOfRange(buffer, from, to);
    }

    public byte[] getBufferUnsafe() {
        return buffer;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public byte[] get() {
        return this.get(this.count - this.offset);
    }

    public byte[] get(int len) {
        if (len < 0) {
            this.offset = this.count - 1;
            return new byte[0];
        }
        len = Math.min(len, this.count - this.offset);
        this.offset += len;
        return Arrays.copyOfRange(this.buffer, this.offset - len, this.offset);
    }

    public void skip(int len) {
        if (len <= 0) {
            return;
        }
        this.offset += Math.min(len, this.count - this.offset);
    }

    public void put(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return;
        }

        this.ensureCapacity(this.count + bytes.length);

        System.arraycopy(bytes, 0, this.buffer, this.count, bytes.length);
        this.count += bytes.length;
    }

    public void put(byte[] bytes, int length) {
        if (bytes == null) {
            return;
        }
        length = Math.min(bytes.length, length);
        if (length <= 0) {
            return;
        }

        this.ensureCapacity(this.count + length);

        System.arraycopy(bytes, 0, this.buffer, this.count, length);
        this.count += length;
    }

    /**
     * 仅用于很小的空数组. 例如1个字节的空数组.
     */
    public void putEmptyBytes(int length) {
        if (length <= 0) {
            return;
        }
        int newLength = this.count + length;
        this.ensureCapacity(newLength);

        for (int i = this.count; i < newLength; i++) {
            this.buffer[i] = 0;
        }
        this.count = newLength;
    }

    private int prepareWriterIndex(int length) {
        this.ensureCapacity(this.count + length);
        int writerIndex = this.count;
        this.count += length;
        return writerIndex;
    }

    public long getLong() {
        return Binary.readLong(this.get(8));
    }

    public void putLong(long l) {
        int index = this.prepareWriterIndex(8);
        Binary.writeLong(l, this.buffer, index);
    }

    public int getInt() {
        return Binary.readInt(this.get(4));
    }

    public void putInt(int i) {
        int index = this.prepareWriterIndex(4);
        Binary.writeInt(i, this.buffer, index);
    }

    public long getLLong() {
        return Binary.readLLong(this.get(8));
    }

    public void putLLong(long l) {
        int index = this.prepareWriterIndex(8);
        Binary.writeLLong(l, this.buffer, index);
    }

    public int getLInt() {
        return Binary.readLInt(this.get(4));
    }

    public void putLInt(int i) {
        int index = this.prepareWriterIndex(4);
        Binary.writeLInt(i, this.buffer, index);
    }

    public int getShort() {
        return Binary.readShort(this.get(2));
    }

    public void putShort(int s) {
        int index = this.prepareWriterIndex(2);
        Binary.writeShort(s, this.buffer, index);
    }

    public int getLShort() {
        return Binary.readLShort(this.get(2));
    }

    public void putLShort(int s) {
        int index = this.prepareWriterIndex(2);
        Binary.writeLShort(s, this.buffer, index);
    }

    public float getFloat() {
        return Binary.readFloat(this.get(4));
    }

    public void putFloat(float v) {
        int index = this.prepareWriterIndex(4);
        Binary.writeFloat(v, this.buffer, index);
    }

    public float getLFloat() {
        return Binary.readLFloat(this.get(4));
    }

    public void putLFloat(float v) {
        int index = this.prepareWriterIndex(4);
        Binary.writeLFloat(v, this.buffer, index);
    }

    public double getDouble() {
        return Binary.readDouble(this.get(8));
    }

    public void putDouble(double v) {
        int index = this.prepareWriterIndex(8);
        Binary.writeDouble(v, this.buffer, index);
    }

    public double getLDouble() {
        return Binary.readLDouble(this.get(8));
    }

    public void putLDouble(double v) {
        int index = this.prepareWriterIndex(8);
        Binary.writeLDouble(v, this.buffer, index);
    }

    public int getTriad() {
        return Binary.readTriad(this.get(3));
    }

    public void putTriad(int triad) {
        int index = this.prepareWriterIndex(3);
        Binary.writeTriad(triad, this.buffer, index);
    }

    public int getLTriad() {
        return Binary.readLTriad(this.get(3));
    }

    public void putLTriad(int triad) {
        int index = this.prepareWriterIndex(3);
        Binary.writeLTriad(triad, this.buffer, index);
    }

    public boolean getBoolean() {
        return this.getByte() == 0x01;
    }

    public void putBoolean(boolean bool) {
        this.putByte((byte) (bool ? 1 : 0));
    }

    public byte getSingedByte() {
        return this.buffer[this.offset++];
    }

    public int getByte() {
        return this.buffer[this.offset++] & 0xff;
    }

    public void putByte(byte b) {
        this.ensureCapacity(this.count + 1);
        this.buffer[this.count++] = b;
    }

    public void putByte(int b) {
        putByte((byte) b);
    }

    public void putUUID(UUID uuid) {
        this.put(Binary.writeUUID(uuid));
    }

    public UUID getUUID() {
        return Binary.readUUID(this.get(16));
    }

    public byte[] getByteArray() {
        int len = (int) this.getUnsignedVarInt();
        if (!isReadable(len)) {
            throw new IndexOutOfBoundsException("array length mismatch");
        }
        return this.get(len);
    }

    public void putByteArray(byte[] b) {
        this.putUnsignedVarInt(b.length);
        this.put(b);
    }

    public byte[] getLByteArray() {
        int len = this.getLInt();
        if (!isReadable(len)) {
            throw new IndexOutOfBoundsException("array length mismatch");
        }
        return this.get(len);
    }

    public void putLByteArray(byte[] b) {
        this.putLInt(b.length);
        this.put(b);
    }

    public String getString() {
        return new String(this.getByteArray(), StandardCharsets.UTF_8);
    }

    public void putString(String string) {
        byte[] b = string.getBytes(StandardCharsets.UTF_8);
        this.putByteArray(b);
    }

    public long getUnsignedVarInt() {
        return VarInt.readUnsignedVarInt(this);
    }

    public void putUnsignedVarInt(long v) {
        VarInt.writeUnsignedVarInt(this, v);
    }

    public int getVarInt() {
        return VarInt.readVarInt(this);
    }

    public void putVarInt(int v) {
        VarInt.writeVarInt(this, v);
    }

    public long getVarLong() {
        return VarInt.readVarLong(this);
    }

    public void putVarLong(long v) {
        VarInt.writeVarLong(this, v);
    }

    public long getUnsignedVarLong() {
        return VarInt.readUnsignedVarLong(this);
    }

    public void putUnsignedVarLong(long v) {
        VarInt.writeUnsignedVarLong(this, v);
    }

    /**
     * Reads and returns an EntityUniqueID
     *
     * @return int
     */
    public long getEntityUniqueId() {
        return this.getVarLong();
    }

    /**
     * Writes an EntityUniqueID
     */
    public void putEntityUniqueId(long eid) {
        this.putVarLong(eid);
    }

    /**
     * Reads and returns an EntityRuntimeID
     */
    public long getEntityRuntimeId() {
        return this.getUnsignedVarLong();
    }

    /**
     * Writes an EntityUniqueID
     */
    public void putEntityRuntimeId(long eid) {
        this.putUnsignedVarLong(eid);
    }

    /**
     * @throws IndexOutOfBoundsException if the length of the array is greater than 4096
     */
    @SuppressWarnings("unchecked")
    public <T> T[] getArray(Class<T> clazz, Function<BinaryStream, T> function) {
        int count = (int) getUnsignedVarInt();
        if (count > 4096) {
            throw new IndexOutOfBoundsException("too many array elements");
        }

        ArrayDeque<T> deque = new ArrayDeque<>();
        for (int i = 0; i < count; i++) {
            deque.add(function.apply(this));
        }
        return deque.toArray((T[]) Array.newInstance(clazz, 0));
    }

    @SuppressWarnings("unchecked")
    public <T> T[] getArrayLInt(Class<T> clazz, Function<BinaryStream, T> function) {
        int count = this.getLInt();
        ArrayDeque<T> deque = new ArrayDeque<>();
        for (int i = 0; i < count; i++) {
            deque.add(function.apply(this));
        }
        return deque.toArray((T[]) Array.newInstance(clazz, 0));
    }

    @SuppressWarnings("unchecked")
    public <T> T[] getArrayLShort(Class<T> clazz, Function<BinaryStream, T> function) {
        int count = this.getLShort();
        ArrayDeque<T> deque = new ArrayDeque<>();
        for (int i = 0; i < count; i++) {
            deque.add(function.apply(this));
        }
        return deque.toArray((T[]) Array.newInstance(clazz, 0));
    }

    @SuppressWarnings("unchecked")
    public <T> T[] getArray(int length, Class<T> clazz, Function<BinaryStream, T> function) {
        ArrayDeque<T> deque = new ArrayDeque<>();
        for (int i = 0; i < length; i++) {
            deque.add(function.apply(this));
        }
        return deque.toArray((T[]) Array.newInstance(clazz, 0));
    }

    public <T> void putOptional(T obj, BiConsumer<BinaryStream, T> consumer) {
        if (obj == null) {
            putBoolean(false);
            return;
        }

        putBoolean(true);
        consumer.accept(this, obj);
    }

    public boolean isReadable(int length) {
        return count - offset >= length;
    }

    public boolean feof() {
        return this.offset < 0 || this.offset >= this.buffer.length;
    }

    private void ensureCapacity(int minCapacity) {
        // overflow-conscious code
        if (minCapacity - buffer.length > 0) {
            grow(minCapacity);
        }
    }

    private void grow(int minCapacity) {
        // overflow-conscious code
        int oldCapacity = buffer.length;
        int newCapacity = oldCapacity << 1;

        if (newCapacity - minCapacity < 0) {
            newCapacity = minCapacity;
        }

        if (newCapacity - MAX_ARRAY_SIZE > 0) {
            newCapacity = hugeCapacity(minCapacity);
        }
        this.buffer = Arrays.copyOf(buffer, newCapacity);
    }

    private static int hugeCapacity(int minCapacity) {
        if (minCapacity < 0) { // overflow
            throw new OutOfMemoryError();
        }
        return (minCapacity > MAX_ARRAY_SIZE) ?
                Integer.MAX_VALUE :
                MAX_ARRAY_SIZE;
    }
}
