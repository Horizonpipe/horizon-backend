package com.horizonpipe.opsmonitor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public final class ConfigStore {
  private static final Path CONFIG_DIR =
      Path.of(System.getProperty("user.home"), ".horizon-ops-monitor");
  private static final Path CONFIG_FILE = CONFIG_DIR.resolve("config.properties");

  private final Properties props = new Properties();

  public ConfigStore() {
    load();
  }

  public String apiBase() {
    return props.getProperty("apiBase", "https://app.horizonpipe.com").trim();
  }

  public String bearerToken() {
    return props.getProperty("bearerToken", "").trim();
  }

  public int pollIntervalMs() {
    try {
      return Math.max(3000, Integer.parseInt(props.getProperty("pollIntervalMs", "8000")));
    } catch (NumberFormatException e) {
      return 8000;
    }
  }

  public void setApiBase(String value) {
    props.setProperty("apiBase", value == null ? "" : value.trim());
  }

  public void setBearerToken(String value) {
    props.setProperty("bearerToken", value == null ? "" : value.trim());
  }

  public void setPollIntervalMs(int ms) {
    props.setProperty("pollIntervalMs", String.valueOf(Math.max(3000, ms)));
  }

  public void load() {
    if (!Files.isRegularFile(CONFIG_FILE)) return;
    try (InputStream in = Files.newInputStream(CONFIG_FILE)) {
      props.load(in);
    } catch (IOException ignored) {
      /* use defaults */
    }
  }

  public void save() throws IOException {
    Files.createDirectories(CONFIG_DIR);
    try (OutputStream out = Files.newOutputStream(CONFIG_FILE)) {
      props.store(out, "Horizon OVH Ops Monitor");
    }
  }

  public boolean isConfigured() {
    return !apiBase().isEmpty() && !bearerToken().isEmpty();
  }
}
