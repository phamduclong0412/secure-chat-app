package org.example;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Date;

public class Home extends JFrame {
    private JPanel HomePanel;
    private JLabel NameJpanel;
    private JTextArea text_area;
    private JTextField Group_input;
    private JButton leave_btn;
    private JButton join_btn;
    private JTextArea Online_area;
    private JTextArea Group_area;
    private JTextField text_input;
    private JButton send_btn;
    private JButton Scan_domain; // Giữ lại khai báo nút Scan_domain
    private JLabel OnlineJLable;
    private JLabel GroupJLable;
    private JButton clearChatButton;
    private JLabel TimeJLable;
    private JButton btnWeather;
    private JLabel ScanStatusLabel; // Giữ lại khai báo ScanStatusLabel

    private SimpleDateFormat timeFormat;
    private String time;

    private String username;
    private NettyClient nettyClient;

    public Home(String username) {
        this.username = username;
        setContentPane(HomePanel);
        setTitle("Chat - " + username);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE); // Keep window until YES_OPTION for exit
        setSize(800, 600);
        setLocationRelativeTo(null);
        setVisible(true);

        text_area.setEditable(false);
        text_area.setLineWrap(true);               // Cho phép xuống dòng tự động
        text_area.setWrapStyleWord(true);          // Xuống dòng theo từ (word) thay vì ký tự        // Xuống dòng theo từ (word) thay vì ký tự




        NameJpanel.setText("Welcome back " + username);


        updateTime();
        Timer timer = new Timer(1000, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateTime();
            }
        });
        timer.start();

        nettyClient = new NettyClient(username);
        try {
            nettyClient.connect("localhost", 9999, msg -> {
                SwingUtilities.invokeLater(() -> {
                    if (msg.contains("@online:")) {
                        int index = msg.indexOf("@online:");
                        String list = msg.substring(index + 8); // sau dấu :
                        String[] users = list.split(",");
                        Online_area.setText(""); // xóa cũ
                        for (String user : users) {
                            Online_area.append(user.trim() + "\n");
                        }

                        // Nếu phần trước @online: là rỗng hoặc chỉ chứa ký tự xuống dòng, thì không in ra
                        String mainMsg = msg.substring(0, index).trim();
                        if (!mainMsg.isEmpty()) {
                            text_area.append(mainMsg + "\n");
                        }
                    } else {
                        text_area.append(msg + "\n");
                    }
                });
            });


        } catch (InterruptedException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Cannot connect to server.");
        }

        send_btn.addActionListener(e -> {
            String msg = text_input.getText().trim();
            if (!msg.isEmpty()) {
                nettyClient.send(msg);
                text_input.setText("");
            }
        });

        join_btn.addActionListener(e -> {
            String group = Group_input.getText().trim();
            if (!group.isEmpty()) {
                nettyClient.send("@join:" + group);
                Group_area.setText("Nhóm hiện tại: " + group);
            }
        });

        leave_btn.addActionListener(e -> {
            nettyClient.send("@leave");
            Group_area.setText("Đã rời nhóm");
        });

        Scan_domain.addActionListener(e -> {
            String domain = "huflit.edu.vn";
            nettyClient.send("@scan:" + domain);
            text_area.append("🔎 Đang scan subdomain cho: " + domain + "\n");
        });



        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                int confirm = JOptionPane.showConfirmDialog(null,
                        "Are you sure you want to exit?", "Exit",
                        JOptionPane.YES_NO_OPTION);
                if (confirm == JOptionPane.YES_OPTION) {
                    nettyClient.close();
                    dispose();
                }
            }
        });


        clearChatButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                text_area.setText("");
            }
        });
        btnWeather.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String weather = "ho chi minh";
                nettyClient.send("@weather:" + weather);

            }
        });
    }


    private void updateTime() {
        SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
        Date now = new Date();
        String timeText = "<html>Thời gian: " + timeFormat.format(now) + "<br>Ngày: " + dateFormat.format(now) + "</html>";
        TimeJLable.setText(timeText);
    }








    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new Home("test_user_1"));
    }
}