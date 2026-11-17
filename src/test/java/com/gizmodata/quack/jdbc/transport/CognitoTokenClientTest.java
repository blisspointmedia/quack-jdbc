package com.gizmodata.quack.jdbc.transport;

import com.gizmodata.quack.jdbc.QuackException;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class CognitoTokenClientTest {
    @Test void validatesTokenResponseShapeAndDoesNotUseIdTokens() throws Exception {
        String valid = CognitoCredentialsTest.tokens("access", "refresh");
        assertEquals("access", CognitoTokenClient.parse(valid.getBytes(StandardCharsets.UTF_8)).accessToken());
        for (String bad : List.of("[]", "{}", valid + "{}", valid.replace("60", "0"), valid.replace("60", "1.5"),
                valid.replace("60", "86401"), valid.replace("Bearer", "Basic"), valid.replace("access_token", "id_token"),
                valid.replace("\"access\"", "null"), valid.replace("access", "a\\nb"),
                valid.replace("{", "{\"access_token\":\"duplicate\","),
                valid.replace("{", "{\"error\":\"invalid_grant\","), valid.substring(0, valid.length() - 1))) {
            assertThrows(IOException.class, () -> CognitoTokenClient.parse(bad.getBytes(StandardCharsets.UTF_8)));
        }
        assertFalse(CognitoTokenClient.parse(valid.getBytes(StandardCharsets.UTF_8)).toString().contains("refresh"));
    }

    @Test void responseLimitCancelsTheBodyAndErrorsDoNotExposeTokens() {
        OAuthTestClient http = new OAuthTestClient(request -> new OAuthTestClient.Reply(200, "sensitive-token" + "x".repeat(65536)));
        var client = new CognitoTokenClient(URI.create("https://login.example/oauth2/token"), "client123", http);
        QuackException error = assertThrows(QuackException.class, () -> client.exchange(Map.of("grant_type", "refresh_token")));
        assertTrue(http.canceled);
        assertNull(error.getCause());
        assertFalse(error.toString().contains("sensitive-token"));
    }

    @Test void redirectsAndMalformedResponsesAreRejectedWithoutRetry() {
        for (int status : List.of(302, 400, 500, 200)) {
            AtomicInteger sends = new AtomicInteger();
            OAuthTestClient http = new OAuthTestClient(request -> {
                sends.incrementAndGet();
                return new OAuthTestClient.Reply(status, "sensitive-token not json");
            });
            var client = new CognitoTokenClient(URI.create("https://login.example/oauth2/token"), "client123", http);
            QuackException error = assertThrows(QuackException.class, () -> client.exchange(Map.of("grant_type", "refresh_token")));
            assertFalse(error.toString().contains("sensitive-token"));
            assertEquals(1, sends.get());
        }
        assertThrows(QuackException.class, () -> new CognitoTokenClient(URI.create("http://login.example/oauth2/token"), "id", HttpClient.newHttpClient()));
        assertThrows(QuackException.class, () -> new CognitoTokenClient(URI.create("https://login.example/oauth2/token"), "id",
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build()));
    }
}
