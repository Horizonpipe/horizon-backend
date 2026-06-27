package com.horizonpipe.opsmonitor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** HTTP client for /ops/* admin API. */
public final class OpsClient {
  private final HttpClient http =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
  private final ObjectMapper mapper = new ObjectMapper();
  private String apiBase;
  private String token;

  public void configure(String apiBase, String token) {
    this.apiBase = apiBase.endsWith("/") ? apiBase.substring(0, apiBase.length() - 1) : apiBase;
    this.token = token;
  }

  public JsonNode get(String path) throws IOException, InterruptedException {
    HttpRequest req =
        HttpRequest.newBuilder()
            .uri(URI.create(apiBase + path))
            .timeout(Duration.ofSeconds(30))
            .header("Authorization", "Bearer " + token)
            .header("Accept", "application/json")
            .GET()
            .build();
    HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
    JsonNode body = mapper.readTree(res.body());
    if (res.statusCode() >= 400) {
      String err = body.has("error") ? body.get("error").asText() : res.body();
      throw new IOException("HTTP " + res.statusCode() + ": " + err);
    }
    return body;
  }

  public JsonNode post(String path, String jsonBody) throws IOException, InterruptedException {
    HttpRequest req =
        HttpRequest.newBuilder()
            .uri(URI.create(apiBase + path))
            .timeout(Duration.ofMinutes(5))
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody == null ? "{}" : jsonBody))
            .build();
    HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
    JsonNode body = mapper.readTree(res.body());
    if (res.statusCode() >= 400) {
      String err = body.has("error") ? body.get("error").asText() : res.body();
      throw new IOException("HTTP " + res.statusCode() + ": " + err);
    }
    return body;
  }

  public static List<Double> extractDoubles(JsonNode samples, String field) {
    List<Double> out = new ArrayList<>();
    if (samples == null || !samples.isArray()) return out;
    for (JsonNode s : samples) {
      out.add(s.has(field) && !s.get(field).isNull() ? s.get(field).asDouble() : 0);
    }
    return out;
  }
}
