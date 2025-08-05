package org.example;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.function.Consumer;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import java.nio.charset.StandardCharsets;

public class NettyClient {
    private Channel channel;
    private EventLoopGroup group;
    private String username;
    private KeyPair keyPair;

    private PublicKey serverPublicKey;
    private final Object serverKeyLock = new Object();

    private SecretKey clientAesKey;
    private final Object aesKeyLock = new Object();

    public NettyClient(String username) {
        this.username = username;
        this.keyPair = generateRSAKeyPair();
    }

    public void connect(String host, int port, Consumer<String> onMessage) throws InterruptedException {
        group = new NioEventLoopGroup();

        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(group)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<SocketChannel>() {
                    protected void initChannel(SocketChannel ch) {
                        ChannelPipeline p = ch.pipeline();
                        // Thêm dòng này để phân tách tin nhắn bằng ký tự xuống dòng
                        p.addLast(new DelimiterBasedFrameDecoder(8192, Unpooled.copiedBuffer("\n", StandardCharsets.UTF_8)));
                        p.addLast(new StringDecoder());
                        p.addLast(new StringEncoder());
                        p.addLast(new SimpleChannelInboundHandler<String>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, String msg) {
                                if (msg.startsWith("[SERVER_PUB_KEY]")) {
                                    try {
                                        String keyString = msg.substring(16);
                                        byte[] keyBytes = Base64.getDecoder().decode(keyString);
                                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                                        synchronized (serverKeyLock) {
                                            serverPublicKey = keyFactory.generatePublic(keySpec);
                                            serverKeyLock.notifyAll();
                                        }
                                        onMessage.accept("✅ Đã nhận public key của server. Sẵn sàng trò chuyện!");
                                    } catch (Exception e) {
                                        onMessage.accept("❌ Lỗi khi nhận public key của server.");
                                        e.printStackTrace();
                                    }
                                } else if (msg.startsWith("[AES_KEY_EXCHANGE]")) {
                                    try {
                                        String encryptedKeyString = msg.substring(18);
                                        byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKeyString);

                                        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                        rsaCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                                        byte[] decodedKeyBytes = rsaCipher.doFinal(encryptedKeyBytes);

                                        synchronized (aesKeyLock) {
                                            clientAesKey = new SecretKeySpec(decodedKeyBytes, 0, decodedKeyBytes.length, "AES");
                                            aesKeyLock.notifyAll();
                                        }
                                        onMessage.accept("✅ Đã nhận và giải mã khóa AES thành công.");
                                    } catch (Exception e) {
                                        onMessage.accept("❌ Lỗi khi giải mã khóa AES từ server.");
                                        e.printStackTrace();
                                    }
                                } else if (msg.startsWith("[ENCRYPTED_MSG]")) {
                                    try {
                                        if (clientAesKey == null) {
                                            onMessage.accept("❌ Lỗi: Chưa có khóa AES để giải mã tin nhắn.");
                                            return;
                                        }

                                        String payload = msg.substring(15);
                                        String[] parts = payload.split("\\|\\|\\|");
                                        if (parts.length != 2) {
                                            onMessage.accept("❌ Lỗi: Định dạng tin nhắn mã hóa không hợp lệ. Payload: " + payload);
                                            return;
                                        }

                                        String encryptedText = parts[0];
                                        String ivString = parts[1];

                                        System.out.println("DEBUG: Client received. EncryptedText: " + encryptedText + ", IVString: " + ivString);

                                        byte[] iv = Base64.getDecoder().decode(ivString);

                                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                        cipher.init(Cipher.DECRYPT_MODE, clientAesKey, new IvParameterSpec(iv));
                                        byte[] decryptedBytes = Base64.getDecoder().decode(encryptedText);
                                        String decryptedMsg = new String(cipher.doFinal(decryptedBytes));

                                        onMessage.accept(decryptedMsg);
                                    } catch (IllegalArgumentException e) {
                                        onMessage.accept("❌ Lỗi giải mã Base64: " + e.getMessage() + ". Dữ liệu lỗi: " + msg);
                                        e.printStackTrace();
                                    } catch (Exception e) {
                                        onMessage.accept("❌ Lỗi khi giải mã tin nhắn: " + e.getMessage());
                                        e.printStackTrace();
                                    }
                                } else {
                                    onMessage.accept(msg);
                                }
                            }
                        });
                    }
                });

        ChannelFuture future = bootstrap.connect(host, port).sync();
        channel = future.channel();

        synchronized (serverKeyLock) {
            while (serverPublicKey == null) {
                serverKeyLock.wait();
            }
        }
        send(username);

        synchronized (aesKeyLock) {
            while (clientAesKey == null) {
                aesKeyLock.wait();
            }
        }
    }

    public void send(String rawMessage) {
        if (serverPublicKey == null) {
            System.err.println("❌ Lỗi: Chưa nhận được public key của server. Không thể gửi tin nhắn.");
            return;
        }
      // Kí tin nhắn bằng Private Key
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(rawMessage.getBytes());
            byte[] signedBytes = signature.sign();

         // Tạo khóa ngẩu nhiên
            byte[] aesKey = new byte[16];
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(aesKey);
            new SecureRandom().nextBytes(iv);

         // mã hóa key AES vừa tạo bằng public key của server
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            // Mã hóa khóa công khai client bằng AES client
            aesCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encryptedPubKey = aesCipher.doFinal(keyPair.getPublic().getEncoded());

// Client gửi tên người dùng, chữ ký số và các khóa đã mã hóa
            String fullMessage = "[SIGNED_MSG]" + rawMessage + "|||"
                    + Base64.getEncoder().encodeToString(signedBytes) + "|||"
                    + Base64.getEncoder().encodeToString(encryptedPubKey) + "|||"
                    + Base64.getEncoder().encodeToString(encryptedAesKey) + "|||"
                    + Base64.getEncoder().encodeToString(iv) ;

            channel.writeAndFlush(fullMessage + "\n");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void close() {
        if (channel != null) {
            channel.close();
        }
        if (group != null) {
            group.shutdownGracefully();
        }
    }
}