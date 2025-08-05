package org.example;

import javax.swing.*;
import java.awt.*;
import java.sql.*;

public class LoginFormModern extends JFrame {
    private JTextField emailField;
    private JPasswordField passwordField;

    public LoginFormModern() {
        setTitle("LOGIN");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(700, 600);
        setLocationRelativeTo(null);
        setResizable(false);

        // Giao diện chia trái - phải
        JPanel mainPanel = new JPanel(new BorderLayout());

        // ==== Panel Trái: Logo + Tên ====
        JPanel leftPanel = new JPanel();
        leftPanel.setPreferredSize(new Dimension(280, 400));
        leftPanel.setBackground(new Color(0, 0, 0));
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));

        // Logo
        JLabel logoLabel = new JLabel();
        ImageIcon logoIcon = new ImageIcon(getClass().getResource("/icon/logo-white.png"));
        Image scaledImage = logoIcon.getImage().getScaledInstance(180, 180, Image.SCALE_SMOOTH);
        logoLabel.setIcon(new ImageIcon(scaledImage));
        logoLabel.setAlignmentX(Component.CENTER_ALIGNMENT);



        JLabel copyright = new JLabel("© Kara Company");
        copyright.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        copyright.setForeground(Color.WHITE);
        copyright.setAlignmentX(Component.CENTER_ALIGNMENT);

        leftPanel.add(Box.createVerticalStrut(40));
        leftPanel.add(logoLabel);
        leftPanel.add(Box.createVerticalStrut(10));

        leftPanel.add(Box.createVerticalGlue());
        leftPanel.add(copyright);
        leftPanel.add(Box.createVerticalStrut(15));

        // ==== Panel Phải: Form Đăng nhập ====
        JPanel rightPanel = new JPanel(new GridBagLayout());
        rightPanel.setBackground(Color.WHITE);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 15, 10, 15);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel loginLabel = new JLabel("LOGIN");
        loginLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        loginLabel.setHorizontalAlignment(SwingConstants.CENTER);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        rightPanel.add(loginLabel, gbc);

        gbc.gridwidth = 1;
        gbc.gridy++;
        rightPanel.add(createLabel("Email:"), gbc);

        emailField = createTextField();
        gbc.gridx = 1;
        rightPanel.add(emailField, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        rightPanel.add(createLabel("Password:"), gbc);

        passwordField = createPasswordField();
        gbc.gridx = 1;
        rightPanel.add(passwordField, gbc);

        // Nút Login
        JButton loginBtn = createButton("Login", new Color(0, 102, 102));
        loginBtn.addActionListener(e -> login());
        gbc.gridx = 0;
        gbc.gridy++;
        gbc.gridwidth = 2;
        rightPanel.add(loginBtn, gbc);

        // Link Sign Up
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        bottomPanel.setBackground(Color.WHITE);
        JLabel noAccount = new JLabel("I don't have an account");
        JButton signUpBtn = createButton("Sign Up", new Color(100, 149, 237));
        signUpBtn.setPreferredSize(new Dimension(100, 30));
        signUpBtn.addActionListener(e -> {
            dispose();
            new SignUpFormModern();
        });

        bottomPanel.add(noAccount);
        bottomPanel.add(signUpBtn);

        gbc.gridy++;
        rightPanel.add(bottomPanel, gbc);

        // Thêm panel vào main
        mainPanel.add(leftPanel, BorderLayout.WEST);
        mainPanel.add(rightPanel, BorderLayout.CENTER);
        setContentPane(mainPanel);
        setVisible(true);
    }

    private JLabel createLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        return label;
    }

    private JTextField createTextField() {
        JTextField tf = new JTextField(15);
        tf.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        return tf;
    }

    private JPasswordField createPasswordField() {
        JPasswordField pf = new JPasswordField(15);
        pf.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        return pf;
    }

    private JButton createButton(String text, Color bgColor) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 14));
        btn.setFocusPainted(false);
        btn.setBackground(bgColor);
        btn.setForeground(Color.WHITE);
        return btn;
    }

    private void login() {
        String email = emailField.getText();
        String password = new String(passwordField.getPassword());
        String hashed = DBUtil.hashPassword(password);

        try (Connection conn = DBUtil.getConnection()) {
            PreparedStatement ps = conn.prepareStatement(
                    "SELECT * FROM users WHERE (email=? OR username=?) AND password=?");
            ps.setString(1, email);
            ps.setString(2, email);
            ps.setString(3, hashed);

            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                JOptionPane.showMessageDialog(this, "✅ Login Successful!");
                String username = rs.getString("username");


                dispose(); // Đóng form Login
                new Home(username); // Mở form Home
            } else {
                JOptionPane.showMessageDialog(this, "❌ Invalid credentials.");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(LoginFormModern::new);
    }
}
