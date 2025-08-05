package org.example;

import javax.swing.*;


public class Server extends JFrame {

    private JLabel NameJpanel;
    private JTextArea textArea;
    private JButton send_btn;
    private JPanel Serverpage;
    private JTextField text_input;

    private final NettyServer nettyServer = new NettyServer();

    public Server() {
        setContentPane(Serverpage);
        setTitle("Server Chat");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(800, 500);
        setLocationRelativeTo(null);
        setVisible(true);

        textArea.setEditable(false);
        NameJpanel.setText("🟢 Server UI on port 9999");

        send_btn.addActionListener(e -> {
            String msg = text_input.getText().trim();
            if (!msg.isEmpty()) {
                nettyServer.broadcast("[SERVER] " + msg);
                appendMessage("You: " + msg);
                text_input.setText("");
            }
        });

        nettyServer.start(9999, this::appendMessage);
    }

    private void appendMessage(String msg) {
        SwingUtilities.invokeLater(() -> textArea.append(msg + "\n"));
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(Server::new);
    }
}
