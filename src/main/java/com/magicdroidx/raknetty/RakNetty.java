package com.magicdroidx.raknetty;

import com.magicdroidx.raknetty.handler.session.Session;
import com.magicdroidx.raknetty.listener.ServerListener;
import com.magicdroidx.raknetty.listener.SessionListenerAdapter;
import com.magicdroidx.raknetty.protocol.raknet.session.GameWrapperPacket;

/**
 * RakNetty Project
 * Author: MagicDroidX
 */
public class RakNetty {

    public static final byte[] OFFLINE_MESSAGE_ID = new byte[]{
            (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0x00,
            (byte) 0xfe, (byte) 0xfe, (byte) 0xfe, (byte) 0xfe,
            (byte) 0xfd, (byte) 0xfd, (byte) 0xfd, (byte) 0xfd,
            (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78
    };

    public static final int PROTOCOL_VERSION = 9;

    public static void main(String[] args) throws Exception {

        RakNetServer server = RakNetServer.bootstrap()
                .withListener(new ServerListener() {
                    @Override
                    public void onSessionCreated(Session session) {
                        session.setListener(new SessionListenerAdapter() {
                            @Override
                            public void registered(Session session) {
                                System.out.println(session.address() + " connecting.");
                            }

                            @Override
                            public void connected(Session session) {
                                System.out.println(session.address() + " connected.");
                            }

                            @Override
                            public void packetReceived(Session session, GameWrapperPacket packet) {
                                System.out.println("Received a game packet: \r\n" + packet);
                            }

                            @Override
                            public void disconnected(Session session) {
                                System.out.println(session.address() + " disconnected.");
                            }
                        });
                    }

                    @Override
                    public void onSessionRemoved(Session session, String reason) {
                        System.out.println("Session closed: " + session.address() + " due to " + reason);
                    }
                })
                .withPort(11111)
                .start();

        //server.stop();
    }
}
