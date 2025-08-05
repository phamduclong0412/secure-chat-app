package org.example;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;

import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import java.nio.charset.StandardCharsets;

public class NettyServer {

    private final List<Channel> clientChannels = new CopyOnWriteArrayList<>();
    private final Map<Channel, String> clientUsernames = new ConcurrentHashMap<>();
    private final Map<Channel, String> clientGroups = new ConcurrentHashMap<>();
    private final Map<Channel, SecretKey> clientAesKeys = new ConcurrentHashMap<>();

    private final KeyPair serverKeyPair;
    private final PublicKey serverPublicKey;
    private final PrivateKey serverPrivateKey;

    private Consumer<String> onMessage;

    public NettyServer() {
        this.serverKeyPair = generateRSAKeyPair();
        this.serverPublicKey = this.serverKeyPair.getPublic();
        this.serverPrivateKey = this.serverKeyPair.getPrivate();
    }

    private KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            notifyUI("❌ Lỗi khi tạo cặp khóa RSA cho server: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public void start(int port, Consumer<String> onMessageCallback) {
        this.onMessage = onMessageCallback;

        new Thread(() -> {
            EventLoopGroup boss = new NioEventLoopGroup(1);
            EventLoopGroup worker = new NioEventLoopGroup();

            try {
                ServerBootstrap bootstrap = new ServerBootstrap();
                bootstrap.group(boss, worker)
                        .channel(NioServerSocketChannel.class)
                        .childHandler(new ChannelInitializer<SocketChannel>() {
                            @Override
                            protected void initChannel(SocketChannel ch) {
                                ChannelPipeline p = ch.pipeline();
                                // Thêm dòng này để phân tách tin nhắn bằng ký tự xuống dòng
                                p.addLast(new DelimiterBasedFrameDecoder(8192, Unpooled.copiedBuffer("\n", StandardCharsets.UTF_8)));
                                p.addLast(new StringDecoder());
                                p.addLast(new StringEncoder());
                                p.addLast(new SimpleChannelInboundHandler<String>() {
                                    @Override
                                    public void channelActive(ChannelHandlerContext ctx) {
                                        clientChannels.add(ctx.channel());
                                        notifyUI("🔗 Client joined: " + ctx.channel().remoteAddress());
                                        String publicKeyString = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
                                        ctx.channel().writeAndFlush("[SERVER_PUB_KEY]" + publicKeyString + "\n");
                                    }

                                    @Override
                                    protected void channelRead0(ChannelHandlerContext ctx, String msg) {
                                        Channel ch = ctx.channel();
                                        if (msg.startsWith("[SIGNED_MSG]")) {
                                            handleSignedMessage(ch, msg.substring(12));
                                        } else {
                                            // Xử lý tin nhắn văn bản thường, chỉ chấp nhận khi đã có username và khóa AES
                                            if (clientUsernames.containsKey(ch) && clientAesKeys.containsKey(ch)) {
                                                String fullMsg = clientUsernames.get(ch) + ": " + msg;
                                                notifyUI(fullMsg);
                                                sendEncryptedToAllClients(fullMsg, ch);
                                            } else {
                                                // Bỏ qua các tin nhắn văn bản thô từ client chưa hoàn tất trao đổi khóa
                                                System.err.println("❌ Nhận tin nhắn thô từ client chưa xác thực, bỏ qua.");
                                            }
                                        }
                                    }

                                    @Override
                                    public void channelInactive(ChannelHandlerContext ctx) {
                                        Channel ch = ctx.channel();
                                        clientChannels.remove(ch);
                                        clientGroups.remove(ch);
                                        clientAesKeys.remove(ch);

                                        String username = clientUsernames.remove(ch);
                                        if (username != null) {
                                            String leaveMsg = "📤 " + username + " has left the chat.";
                                            notifyUI(leaveMsg);
                                            sendEncryptedToAllClients(leaveMsg, ch);
                                            updateOnlineUsers();
                                        } else {
                                            notifyUI("❌ Client left (no username): " + ch.remoteAddress());
                                        }
                                    }

                                    @Override
                                    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                                        notifyUI("⚠️ Error: " + cause.getMessage());
                                        ctx.close();
                                    }
                                });
                            }
                        });

                ChannelFuture future = bootstrap.bind(port).sync();
                future.channel().closeFuture().sync();
            } catch (Exception e) {
                notifyUI("❌ Netty server error: " + e.getMessage());
            } finally {
                boss.shutdownGracefully();
                worker.shutdownGracefully();
            }
        }).start();
    }

    public void broadcast(String msg) {
        for (Channel ch : clientChannels) {
            if (ch.isActive() && !clientGroups.containsKey(ch)) {
                ch.writeAndFlush(msg);
            }
        }
    }

    private void notifyUI(String msg) {
        if (onMessage != null) {
            onMessage.accept(msg);
        }
    }

    private void updateOnlineUsers() {
        StringBuilder sb = new StringBuilder("@online:");
        for (String user : clientUsernames.values()) {
            sb.append(user).append(",");
        }
        if (sb.charAt(sb.length() - 1) == ',') {
            sb.setLength(sb.length() - 1);
        }

        String onlineList = sb.toString();
        for (Channel ch : clientChannels) {
            if (ch.isActive()) {
                ch.writeAndFlush(onlineList + "\n");
            }
        }
    }

    private void scanSubdomains(Channel ch, String domain) {
        new Thread(() -> {
            String domainWithoutProtocol = domain.replace("https://", "").replace("http://", "");
            final int MAX_SUBDOMAINS = 100;

            try {
                URL wordlistUrl = new URL("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt");
                BufferedReader reader = new BufferedReader(new InputStreamReader(wordlistUrl.openStream()));

                String subdomain;
                int count = 0;
                StringBuilder result = new StringBuilder("🔍 Scanning top 100 subdomains for " + domainWithoutProtocol + "...\n");

                while ((subdomain = reader.readLine()) != null && count < MAX_SUBDOMAINS) {
                    count++;
                    String fullDomain = subdomain + "." + domainWithoutProtocol;
                    try {
                        InetAddress.getByName(fullDomain);
                        result.append("✅ Found: ").append(fullDomain).append("\n");
                    } catch (UnknownHostException ignored) {
                        // ignore
                    }
                }

                reader.close();

                if (count >= MAX_SUBDOMAINS) {
                    result.append("⚠️ Đã kiểm tra hết 100 subdomains.\n");
                }

                sendEncryptedToClient(ch, result.toString());

            } catch (Exception e) {
                sendEncryptedToClient(ch, "❌ Scan error: " + e.getMessage() + "\n");
            }
        }).start();
    }

    private JSONObject getLocationData(String city) {
        city = city.replaceAll(" ", "+");
        String urlString = "https://geocoding-api.open-meteo.com/v1/search?name=" +
                city + "&count=1&language=en&format=json";

        try {
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }

                JSONParser parser = new JSONParser();
                JSONObject resultsJsonObj = (JSONObject) parser.parse(response.toString());
                JSONArray locationData = (JSONArray) resultsJsonObj.get("results");

                return (JSONObject) locationData.get(0);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String getWeatherInfo(double latitude, double longitude) {
        String url = "https://api.open-meteo.com/v1/forecast?latitude=" + latitude +
                "&longitude=" + longitude + "&current_weather=true";

        try {
            URL apiUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) apiUrl.openConnection();
            conn.setRequestMethod("GET");

            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }

                JSONParser parser = new JSONParser();
                JSONObject jsonObject = (JSONObject) parser.parse(response.toString());
                JSONObject currentWeatherJson = (JSONObject) jsonObject.get("current_weather");

                String time = (String) currentWeatherJson.get("time");
                double temperature = (double) currentWeatherJson.get("temperature");
                double windSpeed = (double) currentWeatherJson.get("windspeed");

                return String.format("📍 Thời tiết tại hiện tại:\n- Thời gian: %s\n- Nhiệt độ: %.1f°C\n- Tốc độ gió: %.1f m/s",
                        time, temperature, windSpeed);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "❌ Không thể lấy thông tin thời tiết.";
    }

    private void handleSignedMessage(Channel ch, String payload) {
        try {
            String[] parts = payload.split("\\|\\|\\|");
            if (parts.length != 5) {
                ch.writeAndFlush("❌ Định dạng chữ ký sai.\n");
                return;
            }

            String rawMessage = parts[0];
            byte[] signature = Base64.getDecoder().decode(parts[1]);
            byte[] encryptedPubKey = Base64.getDecoder().decode(parts[2]);
            byte[] encryptedAesKey = Base64.getDecoder().decode(parts[3]);
            byte[] iv = Base64.getDecoder().decode(parts[4]);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            byte[] aesKey = rsaCipher.doFinal(encryptedAesKey);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aesCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decodedPubKey = aesCipher.doFinal(encryptedPubKey);

            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(decodedPubKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpecX509);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(rawMessage.getBytes());

            if (sig.verify(signature)) {
                String sender = clientUsernames.getOrDefault(ch, "Unknown");
                notifyUI("🔐[Verified] " + sender + ": " + rawMessage);

                if (!clientAesKeys.containsKey(ch)) {
                    // Sau khi xác thực tin nhắn đầu tiên (username), tạo và gửi khóa AES
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(256);
                    SecretKey clientAesKey = keyGen.generateKey();

                    rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
                    byte[] encryptedClientAesKey = rsaCipher.doFinal(clientAesKey.getEncoded());

             // Server mã hóa khóa AES bằng khóa công khai của client và gửi đi
                    ch.writeAndFlush("[AES_KEY_EXCHANGE]" + Base64.getEncoder().encodeToString(encryptedClientAesKey) + "\n");
                    clientAesKeys.put(ch, clientAesKey);

                    // Xử lý lệnh đầu tiên (username) sau khi đã gửi khóa AES
                    handleVerifiedCommand(ch, rawMessage);
                } else {
                    // Xử lý các lệnh đã được xác thực sau khi có khóa AES
                    handleVerifiedCommand(ch, rawMessage);
                }
            } else {
                ch.writeAndFlush("❌ Chữ ký không hợp lệ!\n");
            }

        } catch (Exception e) {
            ch.writeAndFlush("❌ Lỗi xác thực: " + e.getMessage() + "\n");
            e.printStackTrace();
        }
    }

    private void handleVerifiedCommand(Channel ch, String rawMsg) {
        if (!clientUsernames.containsKey(ch)) {
            clientUsernames.put(ch, rawMsg.trim());
            String joinMsg = "✅ " + rawMsg + " has joined the chat.";
            sendEncryptedToAllClients(joinMsg, ch);
            notifyUI(joinMsg);
            updateOnlineUsers();
            return;
        }

        if (rawMsg.startsWith("@join:")) {
            String groupName = rawMsg.substring(6).trim();
            clientGroups.put(ch, groupName);
            sendEncryptedToClient(ch, "🔸 Joined group: " + groupName + "\n");
            notifyUI("🔸 " + clientUsernames.get(ch) + " joined group " + groupName);
            return;
        }

        if (rawMsg.equals("@leave")) {
            clientGroups.remove(ch);
            sendEncryptedToClient(ch, "🔸 Left the group. Now in global chat.\n");
            notifyUI("🔸 " + clientUsernames.get(ch) + " left their group");
            return;
        }

        if (rawMsg.startsWith("@scan:")) {
            scanSubdomains(ch, rawMsg.substring(6).trim());
            return;
        }

        if (rawMsg.startsWith("@weather:")) {
            String city = rawMsg.substring(9).trim();
            JSONObject locationData = getLocationData(city);
            if (locationData != null) {
                double lat = (double) locationData.get("latitude");
                double lon = (double) locationData.get("longitude");
                String weatherInfo = getWeatherInfo(lat, lon);
                sendEncryptedToClient(ch, "thời tiết của " + city + "\n" + weatherInfo + "\n");
            } else {
                sendEncryptedToClient(ch, "❌ Không tìm thấy thông tin vị trí cho: " + city + "\n");
            }
            return;
        }

        String sender = clientUsernames.getOrDefault(ch, "Unknown");
        String fullMsg = sender + ": " + rawMsg;
        String group = clientGroups.get(ch);
        String receiver = (group != null && !group.isEmpty()) ? group : "global";

        try {
            DBUtil.saveMessageToDatabase(sender, receiver, rawMsg);
        } catch (Exception e) {
            notifyUI("❌ Lỗi khi lưu tin nhắn vào database: " + e.getMessage());
            e.printStackTrace();
        }

        sendEncryptedToAllClients(fullMsg, ch);
    }

    private void sendEncryptedToAllClients(String msg, Channel senderChannel) {
        String group = clientGroups.get(senderChannel);
        Collection<Channel> recipients = new CopyOnWriteArrayList<>();

        if (group != null) {
            for (Map.Entry<Channel, String> entry : clientGroups.entrySet()) {
                if (group.equals(entry.getValue()) && entry.getKey().isActive()) {
                    recipients.add(entry.getKey());
                }
            }
        } else {
            for (Channel other : clientChannels) {
                if (other.isActive() && !clientGroups.containsKey(other)) {
                    recipients.add(other);
                }
            }
        }

        for (Channel recipientChannel : recipients) {
            // Chỉ gửi tin nhắn mã hóa nếu client đã có khóa AES
            if (clientAesKeys.containsKey(recipientChannel)) {
                sendEncryptedToClient(recipientChannel, msg);
            } else {
                System.out.println("DEBUG: Bỏ qua gửi tin nhắn cho " + clientUsernames.getOrDefault(recipientChannel, "Unknown") + " vì chưa có khóa AES.");
            }
        }
    }

    private void sendEncryptedToClient(Channel ch, String msg) {
        SecretKey aesKey = clientAesKeys.get(ch);

        if (aesKey == null) {
            System.err.println("❌ Lỗi nghiêm trọng: Không tìm thấy khóa AES cho client " + clientUsernames.getOrDefault(ch, "Unknown") + ". Tin nhắn không được gửi.");
            return;
        }

        try {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            String ivString = Base64.getEncoder().encodeToString(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] encryptedBytes = cipher.doFinal(msg.getBytes("UTF-8"));
            String encryptedMsg = Base64.getEncoder().encodeToString(encryptedBytes);

            System.out.println("DEBUG: Sending encrypted message to " + clientUsernames.getOrDefault(ch, "Unknown"));
            System.out.println("DEBUG: Encrypted Payload: " + "[ENCRYPTED_MSG]" + encryptedMsg + "|||" + ivString);

            ch.writeAndFlush("[ENCRYPTED_MSG]" + encryptedMsg + "|||" + ivString + "\n");
        } catch (Exception e) {
            notifyUI("❌ Lỗi mã hóa tin nhắn cho client " + clientUsernames.getOrDefault(ch, "Unknown") + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
}