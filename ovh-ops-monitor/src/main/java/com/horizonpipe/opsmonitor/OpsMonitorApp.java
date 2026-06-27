package com.horizonpipe.opsmonitor;

import com.fasterxml.jackson.databind.JsonNode;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.io.IOException;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

public final class OpsMonitorApp extends javax.swing.JFrame {
  private final ConfigStore config = new ConfigStore();
  private final OpsClient client = new OpsClient();
  private Timer pollTimer;

  private JLabel statusLabel;
  private JLabel cpuLabel;
  private JLabel memLabel;
  private JLabel diskLabel;
  private JLabel rxLabel;
  private JLabel txLabel;
  private JLabel pm2Label;
  private JLabel hostLabel;
  private JTextArea repoArea;
  private SparklinePanel cpuChart;
  private SparklinePanel memChart;
  private SparklinePanel netChart;
  private JTextArea logArea;
  private JComboBox<String> logSource;
  private javax.swing.JCheckBox logFollow;
  private JTextArea eventsArea;
  private JLabel jobBanner;

  public OpsMonitorApp() {
    super("Horizon OVH Ops Monitor");
    setDefaultCloseOperation(EXIT_ON_CLOSE);
    setSize(960, 720);
    setLocationRelativeTo(null);
    buildUi();
    applyConfig();
    startPolling();
  }

  private void buildUi() {
    var tabs = new javax.swing.JTabbedPane();
    tabs.addTab("Overview", buildOverview());
    tabs.addTab("Metrics", buildMetrics());
    tabs.addTab("Logs", buildLogs());
    tabs.addTab("Events", buildEvents());
    tabs.addTab("Deploy", buildDeploy());

    statusLabel = new JLabel("Not configured");
    statusLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
    var top = new JPanel(new BorderLayout());
    var btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    var settingsBtn = new JButton("Settings");
    settingsBtn.addActionListener(e -> openSettings());
    var refreshBtn = new JButton("Refresh");
    refreshBtn.addActionListener(e -> refreshAll());
    btnRow.add(refreshBtn);
    btnRow.add(settingsBtn);
    top.add(statusLabel, BorderLayout.CENTER);
    top.add(btnRow, BorderLayout.EAST);

    jobBanner = new JLabel(" ");
    jobBanner.setOpaque(true);
    jobBanner.setBackground(new Color(255, 107, 53, 40));
    jobBanner.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
    jobBanner.setVisible(false);

    getContentPane().setLayout(new BorderLayout());
    getContentPane().add(top, BorderLayout.NORTH);
    getContentPane().add(jobBanner, BorderLayout.SOUTH);
    getContentPane().add(tabs, BorderLayout.CENTER);
  }

  private JPanel buildOverview() {
    var p = new JPanel(new BorderLayout(8, 8));
    p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

    hostLabel = new JLabel("—");
    hostLabel.setFont(hostLabel.getFont().deriveFont(Font.BOLD, 14f));

    var grid = new JPanel(new GridLayout(2, 3, 12, 12));
    cpuLabel = metricCard(grid, "CPU");
    memLabel = metricCard(grid, "Memory");
    diskLabel = metricCard(grid, "Disk");
    rxLabel = metricCard(grid, "Network ↓");
    txLabel = metricCard(grid, "Network ↑");
    pm2Label = metricCard(grid, "PM2 workers");

    repoArea = new JTextArea(6, 40);
    repoArea.setEditable(false);
    repoArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

    p.add(hostLabel, BorderLayout.NORTH);
    p.add(grid, BorderLayout.CENTER);
    p.add(new JScrollPane(repoArea), BorderLayout.SOUTH);
    return p;
  }

  private JLabel metricCard(JPanel grid, String title) {
    var card = new JPanel(new BorderLayout());
    card.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(new Color(60, 70, 90)),
        BorderFactory.createEmptyBorder(10, 12, 10, 12)));
    card.add(new JLabel(title), BorderLayout.NORTH);
    var val = new JLabel("—");
    val.setFont(val.getFont().deriveFont(Font.BOLD, 22f));
    card.add(val, BorderLayout.CENTER);
    grid.add(card);
    return val;
  }

  private JPanel buildMetrics() {
    var p = new JPanel(new GridLayout(3, 1, 8, 8));
    p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
    cpuChart = addChart(p, "CPU %", new Color(61, 184, 255));
    memChart = addChart(p, "Memory %", new Color(255, 107, 53));
    netChart = addChart(p, "Bandwidth Mbps (rx+tx)", new Color(34, 197, 94));
    return p;
  }

  private SparklinePanel addChart(JPanel parent, String title, Color color) {
    var wrap = new JPanel(new BorderLayout());
    wrap.add(new JLabel(title), BorderLayout.NORTH);
    var chart = new SparklinePanel();
    chart.setLineColor(color);
    wrap.add(chart, BorderLayout.CENTER);
    parent.add(wrap);
    return chart;
  }

  private JPanel buildLogs() {
    var p = new JPanel(new BorderLayout(8, 8));
    p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
    var bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
    logSource = new JComboBox<>(new String[] {"pm2-out", "pm2-err", "nginx-error"});
    logFollow = new javax.swing.JCheckBox("Auto-refresh", true);
    logSource.addActionListener(e -> loadLogs());
    bar.add(new JLabel("Source:"));
    bar.add(logSource);
    bar.add(logFollow);
    logArea = new JTextArea();
    logArea.setEditable(false);
    logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    p.add(bar, BorderLayout.NORTH);
    p.add(new JScrollPane(logArea), BorderLayout.CENTER);
    return p;
  }

  private JPanel buildEvents() {
    var p = new JPanel(new BorderLayout());
    p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
    eventsArea = new JTextArea();
    eventsArea.setEditable(false);
    eventsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
    p.add(new JScrollPane(eventsArea), BorderLayout.CENTER);
    return p;
  }

  private JPanel buildDeploy() {
    var p = new JPanel(new BorderLayout(8, 8));
    p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

    var info = new JTextArea(
        "GitHub webhooks → " + config.apiBase() + "/ops/webhook/github\n"
            + "Manual deploy pulls main on backend + frontend and reloads PM2.");
    info.setEditable(false);
    info.setBackground(p.getBackground());

    var deployBtn = new JButton("Deploy now");
    deployBtn.addActionListener(e -> runDeploy());

    var rollPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
    var targetBox = new JComboBox<>(new String[] {"both", "backend", "frontend"});
    var refField = new JTextField("HEAD~1", 16);
    var rollBtn = new JButton("Roll back");
    rollBtn.addActionListener(
        e -> runRollback((String) targetBox.getSelectedItem(), refField.getText().trim()));
    rollPanel.add(new JLabel("Target:"));
    rollPanel.add(targetBox);
    rollPanel.add(new JLabel("Ref:"));
    rollPanel.add(refField);
    rollPanel.add(rollBtn);

    var south = new JPanel(new GridLayout(2, 1, 8, 8));
    south.add(deployBtn);
    south.add(rollPanel);

    p.add(new JScrollPane(info), BorderLayout.CENTER);
    p.add(south, BorderLayout.SOUTH);
    return p;
  }

  private void openSettings() {
    var apiField = new JTextField(config.apiBase(), 32);
    var tokenField = new JTextField(config.bearerToken(), 32);
    var panel = new JPanel(new GridLayout(0, 1, 4, 4));
    panel.add(new JLabel("API base URL:"));
    panel.add(apiField);
    panel.add(new JLabel("Bearer token (admin):"));
    panel.add(tokenField);
    int ok =
        JOptionPane.showConfirmDialog(this, panel, "Settings", JOptionPane.OK_CANCEL_OPTION);
    if (ok != JOptionPane.OK_OPTION) return;
    config.setApiBase(apiField.getText());
    config.setBearerToken(tokenField.getText());
    try {
      config.save();
      applyConfig();
      refreshAll();
    } catch (IOException ex) {
      JOptionPane.showMessageDialog(this, ex.getMessage(), "Save failed", JOptionPane.ERROR_MESSAGE);
    }
  }

  private void applyConfig() {
    if (config.isConfigured()) {
      client.configure(config.apiBase(), config.bearerToken());
      statusLabel.setText("Connected to " + config.apiBase());
    } else {
      statusLabel.setText("Open Settings to set API URL and admin token");
    }
  }

  private void startPolling() {
    if (pollTimer != null) pollTimer.stop();
    pollTimer =
        new Timer(config.pollIntervalMs(), e -> refreshAll());
    pollTimer.start();
  }

  private void refreshAll() {
    if (!config.isConfigured()) return;
    runAsync(
        () -> {
          JsonNode status = client.get("/ops/status");
          JsonNode history = client.get("/ops/metrics/history");
          JsonNode events = client.get("/ops/events?limit=80");
          if (logFollow.isSelected()) {
            JsonNode logs =
                client.get("/ops/logs/" + logSource.getSelectedItem() + "?lines=250");
            return new Object[] {status, history, events, logs};
          }
          return new Object[] {status, history, events, null};
        },
        result -> {
          JsonNode status = (JsonNode) result[0];
          JsonNode history = (JsonNode) result[1];
          JsonNode events = (JsonNode) result[2];
          JsonNode logs = (JsonNode) result[3];
          renderOverview(status.get("overview"));
          renderCharts(history.get("samples"));
          renderEvents(events.get("events"));
          if (logs != null) renderLogs(logs);
        },
        err -> statusLabel.setText("Error: " + err.getMessage()));
  }

  private void loadLogs() {
    if (!config.isConfigured()) return;
    runAsync(
        () -> client.get("/ops/logs/" + logSource.getSelectedItem() + "?lines=250"),
        logs -> renderLogs(logs),
        err -> logArea.setText(err.getMessage()));
  }

  private void renderOverview(JsonNode o) {
    if (o == null) return;
    JsonNode m = o.get("metrics");
    hostLabel.setText(
        o.path("host").asText("Server")
            + " · up "
            + (o.path("uptimeSec").asInt(0) / 3600)
            + "h · "
            + o.path("platform").asText(""));
    cpuLabel.setText(m.path("cpuPct").asInt() + "%");
    memLabel.setText(m.path("memUsedGb").asDouble() + " / " + m.path("memTotalGb").asDouble() + " GB");
    diskLabel.setText(m.path("diskUsedPct").asInt() + "%");
    rxLabel.setText(m.path("netRxMbps").asDouble() + " Mbps");
    txLabel.setText(m.path("netTxMbps").asDouble() + " Mbps");
    pm2Label.setText(o.path("pm2").path("online").asInt() + " online");

    var sb = new StringBuilder();
    JsonNode repos = o.get("repos");
    if (repos != null) {
      appendRepo(sb, "backend", repos.get("backend"));
      appendRepo(sb, "frontend", repos.get("frontend"));
    }
    repoArea.setText(sb.toString());

    JsonNode job = o.get("activeJob");
    if (job != null && !job.isNull() && "running".equals(job.path("status").asText())) {
      jobBanner.setText("Job running: " + job.path("type").asText() + " (started " + job.path("startedAt").asText() + ")");
      jobBanner.setVisible(true);
    } else if (job != null && !job.isNull() && "failed".equals(job.path("status").asText())) {
      jobBanner.setText("Last job failed: " + job.path("type").asText());
      jobBanner.setBackground(new Color(220, 38, 38, 60));
      jobBanner.setVisible(true);
    } else {
      jobBanner.setVisible(false);
      jobBanner.setBackground(new Color(255, 107, 53, 40));
    }
  }

  private void appendRepo(StringBuilder sb, String name, JsonNode r) {
    if (r == null) return;
    sb.append(name.toUpperCase()).append(": ");
    if (r.path("ok").asBoolean(false)) {
      sb.append(r.path("hash").asText())
          .append(" ")
          .append(r.path("branch").asText())
          .append("\n  ")
          .append(r.path("subject").asText());
      if (r.path("dirty").asBoolean(false)) sb.append(" (dirty)");
    } else {
      sb.append(r.path("error").asText("unavailable"));
    }
    sb.append("\n\n");
  }

  private void renderCharts(JsonNode samples) {
    cpuChart.setValues(OpsClient.extractDoubles(samples, "cpuPct"));
    memChart.setValues(OpsClient.extractDoubles(samples, "memUsedPct"));
    var net = new java.util.ArrayList<Double>();
    if (samples != null && samples.isArray()) {
      for (JsonNode s : samples) {
        net.add(s.path("netRxMbps").asDouble() + s.path("netTxMbps").asDouble());
      }
    }
    netChart.setValues(net);
  }

  private void renderEvents(JsonNode events) {
    if (events == null || !events.isArray() || events.isEmpty()) {
      eventsArea.setText("No events yet.");
      return;
    }
    var sb = new StringBuilder();
    for (JsonNode ev : events) {
      sb.append(ev.path("at").asText())
          .append("  [")
          .append(ev.path("type").asText())
          .append("]  ")
          .append(ev.path("message").asText())
          .append("\n");
    }
    eventsArea.setText(sb.toString());
    eventsArea.setCaretPosition(0);
  }

  private void renderLogs(JsonNode logs) {
    if (logs.has("error")) {
      logArea.setText(logs.get("error").asText());
      return;
    }
    JsonNode lines = logs.get("lines");
    if (lines == null || !lines.isArray()) {
      logArea.setText("(empty)");
      return;
    }
    var sb = new StringBuilder();
    for (JsonNode line : lines) sb.append(line.asText()).append("\n");
    logArea.setText(sb.toString());
    logArea.setCaretPosition(logArea.getDocument().getLength());
  }

  private void runDeploy() {
    if (JOptionPane.showConfirmDialog(this, "Pull latest main and reload PM2?", "Deploy", JOptionPane.YES_NO_OPTION)
        != JOptionPane.YES_OPTION) return;
    runAsync(
        () -> client.post("/ops/deploy", "{\"reason\":\"desktop-manual\"}"),
        r -> {
          JOptionPane.showMessageDialog(this, "Deploy finished.");
          refreshAll();
        },
        err -> JOptionPane.showMessageDialog(this, err.getMessage(), "Deploy failed", JOptionPane.ERROR_MESSAGE));
  }

  private void runRollback(String target, String ref) {
    if (ref.isEmpty()) {
      JOptionPane.showMessageDialog(this, "Enter a git ref.");
      return;
    }
    if (JOptionPane.showConfirmDialog(this, "Roll back " + target + " to " + ref + "?", "Rollback", JOptionPane.YES_NO_OPTION)
        != JOptionPane.YES_OPTION) return;
    String body = "{\"target\":\"" + target + "\",\"ref\":\"" + ref.replace("\"", "") + "\"}";
    runAsync(
        () -> client.post("/ops/rollback", body),
        r -> {
          JOptionPane.showMessageDialog(this, "Rollback finished.");
          refreshAll();
        },
        err -> JOptionPane.showMessageDialog(this, err.getMessage(), "Rollback failed", JOptionPane.ERROR_MESSAGE));
  }

  private void runAsync(
      ThrowingSupplier<Object> work,
      Consumer<Object> onSuccess,
      Consumer<Exception> onError) {
    new Thread(
            () -> {
              try {
                Object result = work.get();
                SwingUtilities.invokeLater(() -> onSuccess.accept(result));
              } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> onError.accept(ex));
              }
            },
            "ops-poll")
        .start();
  }

  @FunctionalInterface
  interface ThrowingSupplier<T> {
    T get() throws Exception;
  }

  public static void main(String[] args) {
    SwingUtilities.invokeLater(
        () -> {
          try {
            javax.swing.UIManager.setLookAndFeel(javax.swing.UIManager.getSystemLookAndFeelClassName());
          } catch (Exception ignored) {
          }
          new OpsMonitorApp().setVisible(true);
        });
  }
}
