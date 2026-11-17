package com.gizmodata.quack.jdbc.transport;

import com.gizmodata.quack.jdbc.QuackException;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class CognitoTokenHttpsTest {
    @TempDir Path directory;

    private SSLContext tls() throws Exception {
        Path store = directory.resolve("loopback.p12");
        Process keytool = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "loopback", "-keyalg", "RSA", "-keysize", "2048", "-validity", "1",
                "-dname", "CN=localhost", "-ext", "SAN=ip:127.0.0.1,dns:localhost", "-storetype", "PKCS12",
                "-keystore", store.toString(), "-storepass", "fixture-password", "-keypass", "fixture-password", "-noprompt")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try { assertTrue(keytool.waitFor(15, TimeUnit.SECONDS)); assertEquals(0, keytool.exitValue()); }
        finally { keytool.destroyForcibly(); }
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) { keys.load(input, "fixture-password".toCharArray()); }
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keys, "fixture-password".toCharArray());
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(keys);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), trust.getTrustManagers(), null);
        return context;
    }

    @Test void fullExchangeDeadlineIncludesAStalledTlsResponseBody() throws Exception {
        SSLContext tls = tls();
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger responses = new AtomicInteger();
        server.createContext("/oauth2/token", exchange -> {
            try (exchange) {
                exchange.getRequestBody().readAllBytes();
                exchange.sendResponseHeaders(200, 100);
                exchange.getResponseBody().write('{');
                exchange.getResponseBody().flush();
                responses.incrementAndGet();
                try { release.await(15, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            } catch (IOException ignored) { } // The deadline cancels the unfinished body.
        });
        server.start();
        try {
            var client = new CognitoTokenClient(URI.create("https://127.0.0.1:" + server.getAddress().getPort() + "/oauth2/token"),
                    "client123", HttpClient.newBuilder().sslContext(tls).connectTimeout(Duration.ofSeconds(2)).build());
            long started = System.nanoTime();
            assertThrows(QuackException.class, () -> client.exchange(Map.of("grant_type", "refresh_token", "refresh_token", "synthetic")));
            long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertEquals(1, responses.get());
            assertTrue(elapsed >= 8500 && elapsed < 15000, "full-body deadline elapsed ms: " + elapsed);
        } finally { release.countDown(); server.stop(0); }
    }

    @Test void defaultTlsRejectsUntrustedProviderAndTrustedTlsParsesResponse() throws Exception {
        SSLContext tls = tls();
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        AtomicInteger requests = new AtomicInteger();
        server.createContext("/oauth2/token", exchange -> {
            try (exchange) {
                requests.incrementAndGet();
                exchange.getRequestBody().readAllBytes();
                byte[] body = CognitoCredentialsTest.tokens("access", "refresh").getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            }
        });
        server.start();
        try {
            URI uri = URI.create("https://127.0.0.1:" + server.getAddress().getPort() + "/oauth2/token");
            var untrusted = new CognitoTokenClient(uri, "client123", HttpClient.newHttpClient());
            assertThrows(QuackException.class, () -> untrusted.exchange(Map.of("grant_type", "refresh_token")));
            assertEquals(0, requests.get());
            var trusted = new CognitoTokenClient(uri, "client123", HttpClient.newBuilder().sslContext(tls).build());
            assertEquals("access", trusted.exchange(Map.of("grant_type", "refresh_token")).accessToken());
            assertEquals(1, requests.get());
        } finally { server.stop(0); }
    }
}
