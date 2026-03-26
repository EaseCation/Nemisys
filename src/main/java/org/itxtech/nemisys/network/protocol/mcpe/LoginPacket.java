package org.itxtech.nemisys.network.protocol.mcpe;

import lombok.ToString;
import lombok.extern.log4j.Log4j2;
import org.itxtech.nemisys.utils.ClientChainData;
import org.itxtech.nemisys.utils.LoginChainData;
import org.itxtech.nemisys.utils.TextFormat;

/**
 * Created by on 15-10-13.
 */
@Log4j2
@ToString
public class LoginPacket extends DataPacket {

    public static final int NETWORK_ID = ProtocolInfo.LOGIN_PACKET;

    public int protocol;
    public LoginChainData loginChainData;

    public transient byte[] cacheBuffer;

    @Override
    public int pid() {
        return NETWORK_ID;
    }

    @Override
    public boolean canBeSentBeforeLogin() {
        return true;
    }

    @Override
    public void decode() {
        int start = this.getOffset();
        this.cacheBuffer = this.getBuffer();
        this.protocol = this.getInt();

        if (start == 1 && this.protocol <= 113) {
            getByte();
        }

        decodeChainData(this.getByteArray());
    }

    public void decodeChainData(byte[] buffer) {
        try {
            loginChainData = ClientChainData.of(buffer, protocol);

            switch (loginChainData.getAuthenticationOffer()) {
                case LoginChainData.AUTHENTICATION_OFFER_EASECATION:
                    log.debug("[Login] {} {}内网验证通过: {}", loginChainData.getUsername(), TextFormat.YELLOW, protocol);
                    break;
                case LoginChainData.AUTHENTICATION_OFFER_NETEASE:
                    log.debug("[Login] {} {}中国版验证通过: {}", loginChainData.getUsername(), TextFormat.RED, protocol);
                    break;
                case LoginChainData.AUTHENTICATION_OFFER_MOJANG:
                    log.debug("[Login] {} {}国际版验证通过: {}", loginChainData.getUsername(), TextFormat.GREEN, protocol);
                    break;
                case LoginChainData.AUTHENTICATION_OFFER_INVALID:
                    log.debug("[Login] {} {}在线验证失败! {}", loginChainData.getUsername(), TextFormat.BLUE, protocol);
                    break;
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.throwing(e);
            }
        }
    }
}
