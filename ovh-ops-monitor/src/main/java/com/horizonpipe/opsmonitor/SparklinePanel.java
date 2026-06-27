package com.horizonpipe.opsmonitor;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JPanel;

public final class SparklinePanel extends JPanel {
  private final List<Double> values = new ArrayList<>();
  private Color lineColor = new Color(61, 184, 255);

  public SparklinePanel() {
    setPreferredSize(new Dimension(400, 120));
    setBackground(new Color(24, 28, 36));
  }

  public void setLineColor(Color c) {
    this.lineColor = c;
  }

  public void setValues(List<Double> v) {
    values.clear();
    if (v != null) values.addAll(v);
    repaint();
  }

  @Override
  protected void paintComponent(Graphics g) {
    super.paintComponent(g);
    Graphics2D g2 = (Graphics2D) g;
    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
    int w = getWidth();
    int h = getHeight();
    if (values.isEmpty()) return;
    double max = 1;
    for (double v : values) max = Math.max(max, v);
    g2.setStroke(new BasicStroke(2f));
    g2.setColor(lineColor);
    for (int i = 0; i < values.size(); i++) {
      double v = values.get(i);
      int x = (int) ((i / (double) Math.max(1, values.size() - 1)) * (w - 16) + 8);
      int y = (int) (h - 8 - (v / max) * (h - 16));
      if (i == 0) g2.drawLine(x, y, x, y);
      else {
        double pv = values.get(i - 1);
        int px = (int) (((i - 1) / (double) Math.max(1, values.size() - 1)) * (w - 16) + 8);
        int py = (int) (h - 8 - (pv / max) * (h - 16));
        g2.drawLine(px, py, x, y);
      }
    }
  }
}
