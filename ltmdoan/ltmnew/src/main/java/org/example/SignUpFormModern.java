package org.example;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SignUpFormModern extends JFrame {

    private JTextField usernameField, emailField, addressField, phoneField;
    private JPasswordField passwordField, confirmPasswordField;

    public SignUpFormModern() {
        setTitle("SIGN UP");
        setSize(820, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        // Left Panel (Logo)
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBackground(new Color(0, 0, 0));
        leftPanel.setPreferredSize(new Dimension(280, 0));

        JLabel logoLabel = new JLabel();
        ImageIcon logoIcon = new ImageIcon(getClass().getResource("/icon/logo-white.png"));
        Image scaledImage = logoIcon.getImage().getScaledInstance(150, 150, Image.SCALE_SMOOTH);
        logoLabel.setIcon(new ImageIcon(scaledImage));
        logoLabel.setHorizontalAlignment(SwingConstants.CENTER);
        leftPanel.add(logoLabel, BorderLayout.CENTER);

        JLabel company = new JLabel("© Kara Company", SwingConstants.CENTER);
        company.setForeground(Color.LIGHT_GRAY);
        company.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        leftPanel.add(company, BorderLayout.SOUTH);

        add(leftPanel, BorderLayout.WEST);

        // Right Panel (Form)
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
        rightPanel.setBackground(Color.WHITE);
        rightPanel.setBorder(BorderFactory.createEmptyBorder(30, 40, 30, 40));

        JLabel title = new JLabel("CREATE ACCOUNT");
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        title.setFont(new Font("Segoe UI", Font.BOLD, 20));
        title.setForeground(Color.WHITE);
        rightPanel.add(title);
        rightPanel.add(Box.createRigidArea(new Dimension(0, 20)));

        usernameField = createFieldWithLabel(rightPanel, "Username:");
        emailField = createFieldWithLabel(rightPanel, "Email:");
        passwordField = createPasswordWithLabel(rightPanel, "Password:");
        confirmPasswordField = createPasswordWithLabel(rightPanel, "Confirm Password:");
        addressField = createFieldWithLabel(rightPanel, "Address:");
        phoneField = createFieldWithLabel(rightPanel, "Phone:");

        rightPanel.add(Box.createRigidArea(new Dimension(0, 20)));

        JButton signupBtn = new JButton("Sign Up");
        signupBtn.setBackground(new Color(0, 153, 204));
        signupBtn.setForeground(Color.WHITE);
        signupBtn.setFocusPainted(false);
        signupBtn.setFont(new Font("Segoe UI", Font.BOLD, 14));
        signupBtn.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
        signupBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        signupBtn.addActionListener(this::handleSignUp);





        rightPanel.add(signupBtn);


        //nut back ve trang login

        JButton backBtn = new JButton("← Back to Login");
        backBtn.setBackground(Color.LIGHT_GRAY);
        backBtn.setForeground(Color.BLACK);
        backBtn.setFocusPainted(false);
        backBtn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        backBtn.setBorder(BorderFactory.createEmptyBorder(8, 20, 8, 20));
        backBtn.setAlignmentX(Component.CENTER_ALIGNMENT);

        backBtn.addActionListener(e -> {
            dispose(); // đóng form hiện tại
            new org.example.LoginFormModern(); // mở lại login form
        }); rightPanel.add(Box.createRigidArea(new Dimension(0, 10)));
        rightPanel.add(backBtn);


        add(rightPanel, BorderLayout.CENTER);
        setVisible(true);
    }

    private JTextField createFieldWithLabel(JPanel panel, String labelText) {
        JLabel label = new JLabel(labelText);
        label.setForeground(Color.DARK_GRAY); // label màu đậm
        label.setFont(new Font("Segoe UI", Font.PLAIN, 14));

        JTextField field = new JTextField(20);
        field.setBackground(Color.WHITE);         // Nền trắng
        field.setForeground(Color.BLACK);         // Text đen
        field.setCaretColor(Color.BLACK);         // Dấu nháy đen
        field.setBorder(BorderFactory.createLineBorder(new Color(180, 180, 180))); // viền nhẹ
        field.setFont(new Font("Segoe UI", Font.PLAIN, 14));

        panel.add(label);
        panel.add(field);
        panel.add(Box.createRigidArea(new Dimension(0, 10)));
        return field;
    }


    private JPasswordField createPasswordWithLabel(JPanel panel, String labelText) {
        JLabel label = new JLabel(labelText);
        label.setForeground(Color.DARK_GRAY);
        label.setFont(new Font("Segoe UI", Font.PLAIN, 14));

        JPasswordField field = new JPasswordField(20);
        field.setBackground(Color.WHITE);
        field.setForeground(Color.BLACK);
        field.setCaretColor(Color.BLACK);
        field.setBorder(BorderFactory.createLineBorder(new Color(180, 180, 180)));
        field.setFont(new Font("Segoe UI", Font.PLAIN, 14));

        panel.add(label);
        panel.add(field);
        panel.add(Box.createRigidArea(new Dimension(0, 10)));
        return field;
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not supported", e);
        }
    }


    private void handleSignUp(ActionEvent e) {
        String username = usernameField.getText().trim();
        String email = emailField.getText().trim();
        String password = String.valueOf(passwordField.getPassword());
        String confirmPassword = String.valueOf(confirmPasswordField.getPassword());
        String address = addressField.getText().trim();
        String phone = phoneField.getText().trim();

        if (!password.equals(confirmPassword)) {
            JOptionPane.showMessageDialog(this, "Passwords do not match!", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try (Connection conn = DBUtil.getConnection()) {
            String sql = "INSERT INTO users (username, email, password, address, phone) VALUES (?, ?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, username);
            stmt.setString(2, email);
            stmt.setString(3, hashPassword(password));
            stmt.setString(4, address);
            stmt.setString(5, phone);
            stmt.executeUpdate();

            JOptionPane.showMessageDialog(this, "Sign up successful!");

        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "Sign up failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SignUpFormModern::new);
    }
}
