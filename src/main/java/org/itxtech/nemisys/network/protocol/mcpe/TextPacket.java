package org.itxtech.nemisys.network.protocol.mcpe;

import lombok.ToString;
import org.itxtech.nemisys.utils.BinaryStream;
import org.itxtech.nemisys.utils.Utils;

/**
 * Created on 15-10-13.
 */
@ToString
public class TextPacket extends DataPacket {

    public static final int NETWORK_ID = ProtocolInfo.TEXT_PACKET;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    public static final byte TYPE_RAW = 0;
    public static final byte TYPE_CHAT = 1;
    public static final byte TYPE_TRANSLATION = 2;
    public static final byte TYPE_POPUP = 3;
    public static final byte TYPE_JUKEBOX_POPUP = 4;
    public static final byte TYPE_TIP = 5;
    public static final byte TYPE_SYSTEM = 6;
    public static final byte TYPE_WHISPER = 7;
    public static final byte TYPE_ANNOUNCEMENT = 8;
    public static final byte TYPE_OBJECT = 9;
    public static final byte TYPE_OBJECT_WHISPER = 10;
    public static final byte TYPE_OBJECT_ANNOUNCEMENT = 11;

    public static final byte BODY_TYPE_MESSAGE_ONLY = 0;
    public static final byte BODY_TYPE_AUTHOR_AND_MESSAGE = 1;
    public static final byte BODY_TYPE_MESSAGE_AND_PARAMS = 2;

    private static final int MAX_MESSAGE_LENGTH = 65536;
    private static final int MAX_AUTHOR_LENGTH = 256;
    private static final int MAX_PARAMETER = 4;
    private static final int MAX_PARAMETER_NETEASE = 12;
    private static final int MAX_XUID_LENGTH = 64;
    private static final int MAX_PLATFORM_ID_LENGTH = 256;

    public byte type;
    public boolean isLocalized = false;

    public String message = "";
    public String[] parameters = new String[0]; // max: 4 || 12 (netease)
    public String primaryName = "";

    public String sendersXUID = "";
    public String platformIdString = "";
    public String filteredMessage = "";

    @Override
    public void decode(int protocol, boolean netease) {
    }

    @Override
    public void encode(int protocol, boolean netease) {
        this.reset(protocol);
        if (protocol < 878) {
            this.putByte(this.type);
        }
        this.putBoolean(this.isLocalized);
        String message = this.message;
        if (protocol >= 898 && message.isEmpty()) {
            message = " ";
        }
        switch (this.type) {
            case TYPE_CHAT:
            case TYPE_WHISPER:
            case TYPE_ANNOUNCEMENT:
                if (protocol >= 878) {
                    this.putByte(BODY_TYPE_AUTHOR_AND_MESSAGE);
                    if (protocol < 923) {
                        this.put(BODY_MAGIC_AUTHOR_AND_MESSAGE);
                    }
                    this.putByte(this.type);
                }
                this.putString(primaryName, MAX_AUTHOR_LENGTH);
                this.putString(message, MAX_MESSAGE_LENGTH);

                if (netease && protocol >= 898) { // netease only
                    this.putArray(this.parameters, BinaryStream::putString, MAX_PARAMETER_NETEASE);
                }

                break;
            case TYPE_RAW:
            case TYPE_TIP:
            case TYPE_SYSTEM:
            case TYPE_OBJECT:
            case TYPE_OBJECT_WHISPER:
            case TYPE_OBJECT_ANNOUNCEMENT:
                if (protocol >= 878) {
                    this.putByte(BODY_TYPE_MESSAGE_ONLY);
                    if (protocol < 923) {
                        this.put(BODY_MAGIC_MESSAGE_ONLY);
                    }
                    this.putByte(this.type);
                }
                this.putString(message, MAX_MESSAGE_LENGTH);
                break;
            case TYPE_TRANSLATION:
            case TYPE_POPUP:
            case TYPE_JUKEBOX_POPUP:
                if (protocol >= 878) {
                    this.putByte(BODY_TYPE_MESSAGE_AND_PARAMS);
                    if (protocol < 923) {
                        this.put(BODY_MAGIC_MESSAGE_AND_PARAMS);
                    }
                    this.putByte(this.type);
                }
                this.putString(message, MAX_MESSAGE_LENGTH);
                this.putArray(this.parameters, BinaryStream::putString, netease ? MAX_PARAMETER_NETEASE : MAX_PARAMETER);
                break;
        }
        this.putString(sendersXUID, MAX_XUID_LENGTH);
        this.putString(platformIdString, MAX_PLATFORM_ID_LENGTH);
        if (protocol >= 685) {
            if (protocol >= 898) {
                this.putBoolean(!filteredMessage.isEmpty());
                if (!filteredMessage.isEmpty()) {
                    this.putString(filteredMessage, MAX_MESSAGE_LENGTH);
                }
            } else {
                this.putString(filteredMessage);
            }
        }

        if (netease && protocol >= 410 && protocol <= 860) { // netease only
            if (type == TYPE_CHAT || type == TYPE_POPUP) {
                this.putUnsignedVarInt(0);
            }
        }
    }

    @Override
    public void tryEncode(int protocol, boolean netease) {
        if (!this.isEncoded) {
            this.isEncoded = true;
            this.encode(protocol, netease);
        }
    }

    private static final byte[] BODY_MAGIC_MESSAGE_ONLY = Utils.make(() -> {
        BinaryStream stream = new BinaryStream();
        stream.putString("raw");
        stream.putString("tip");
        stream.putString("systemmessage");
        stream.putString("textobjectwhisper");
        stream.putString("textobjectannouncement");
        stream.putString("textobject");
        return stream.getBuffer();
    });
    private static final byte[] BODY_MAGIC_AUTHOR_AND_MESSAGE = Utils.make(() -> {
        BinaryStream stream = new BinaryStream();
        stream.putString("chat");
        stream.putString("whisper");
        stream.putString("announcement");
        return stream.getBuffer();
    });
    private static final byte[] BODY_MAGIC_MESSAGE_AND_PARAMS = Utils.make(() -> {
        BinaryStream stream = new BinaryStream();
        stream.putString("translate");
        stream.putString("popup");
        stream.putString("jukeboxpopup");
        return stream.getBuffer();
    });
}
