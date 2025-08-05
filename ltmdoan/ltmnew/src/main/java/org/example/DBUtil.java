package org.example;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections; // THÊM IMPORT NÀY
import java.util.List;
import java.util.Set;
import java.util.HashSet;

public class DBUtil {
    public static Connection getConnection() throws SQLException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.err.println("MySQL JDBC Driver not found! Make sure you have added the MySQL Connector/J to your project.");
            throw new SQLException("MySQL JDBC Driver not found.", e);
        }
        return DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/userdb?useSSL=false&serverTimezone=UTC", "root", ""
        );
    }

    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashed = md.digest(password.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashed) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static void saveMessageToDatabase(String sender, String receiver, String message) {
        String sql = "INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)";

        // Gán giá trị mặc định "global" nếu receiver là null hoặc rỗng
        String finalReceiver = (receiver == null || receiver.isEmpty()) ? "global" : receiver;

        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, sender);
            pstmt.setString(2, finalReceiver); // Sử dụng giá trị đã kiểm tra
            pstmt.setString(3, message);

            pstmt.executeUpdate();
            System.out.println("✅ Tin nhắn đã được lưu vào database.");

        } catch (SQLException e) {
            System.err.println("❌ Lỗi khi lưu tin nhắn vào database: " + e.getMessage());
            e.printStackTrace();
        }
    }

}