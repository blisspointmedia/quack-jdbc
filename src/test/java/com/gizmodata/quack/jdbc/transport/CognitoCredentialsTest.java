package com.gizmodata.quack.jdbc.transport;

import com.gizmodata.quack.jdbc.QuackException;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

class CognitoCredentialsTest {
    static CognitoCredentials.Config config() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return new CognitoCredentials.Config(URI.create("https://login.example"), "client123", "openid email query/read", socket.getLocalPort());
        }
    }

    static String tokens(String access, String refresh) {
        return "{\"access_token\":\"" + access + "\",\"token_type\":\"Bearer\",\"expires_in\":60"
                + (refresh == null ? "" : ",\"refresh_token\":\"" + refresh + "\"") + "}";
    }

    static int callback(URI redirect, String query) {
        try {
            return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(redirect + "?" + query))
                    .timeout(Duration.ofSeconds(2)).GET().build(), HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (Exception e) { throw new AssertionError(e); }
    }

    static Consumer<URI> browser(AtomicInteger calls) {
        return uri -> {
            calls.incrementAndGet();
            Map<String, String> fields = LoopbackLogin.parseQuery(uri.getRawQuery());
            assertEquals("S256", fields.get("code_challenge_method"));
            assertEquals("code", fields.get("response_type"));
            assertEquals(200, callback(URI.create(fields.get("redirect_uri")), LoopbackLogin.form(
                    Map.of("state", fields.get("state"), "code", "one-time-code"))));
        };
    }

    static CognitoCredentials credentials(CognitoCredentials.Config config, OAuthTestClient client,
                                          Consumer<URI> browser, AtomicLong clock) {
        return new CognitoCredentials(config, new CognitoTokenClient(config.domain().resolve("/oauth2/token"),
                config.clientId(), client), browser, clock::get);
    }

    @Test void browserPkceAndRefreshRotationStayWithinOneCredentialSession() throws Exception {
        var config = config();
        AtomicLong clock = new AtomicLong();
        AtomicInteger browsers = new AtomicInteger();
        AtomicReference<String> challenge = new AtomicReference<>();
        List<Map<String, String>> grants = new ArrayList<>();
        OAuthTestClient client = new OAuthTestClient(request -> {
            assertEquals(config.domain().resolve("/oauth2/token"), request.uri());
            assertEquals(Duration.ofSeconds(10), request.timeout().orElseThrow());
            Map<String, String> grant = OAuthTestClient.form(request);
            assertEquals("client123", grant.get("client_id"));
            grants.add(grant);
            return new OAuthTestClient.Reply(200, tokens("access" + grants.size(), grants.size() == 3 ? null : "refresh" + grants.size()));
        });
        CognitoCredentials credentials = credentials(config, client, uri -> {
            challenge.set(LoopbackLogin.parseQuery(uri.getRawQuery()).get("code_challenge"));
            browser(browsers).accept(uri);
        }, clock);
        assertEquals("access1", credentials.token());
        String verifier = grants.get(0).get("code_verifier");
        assertEquals(challenge.get(), Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII))));
        assertEquals(config.redirect().toString(), grants.get(0).get("redirect_uri"));
        assertEquals("one-time-code", grants.get(0).get("code"));
        for (int i = 0; i < 10; i++) assertEquals("access1", credentials.token());
        assertEquals(1, grants.size());
        clock.set(TimeUnit.SECONDS.toNanos(55));
        assertEquals("access2", credentials.token());
        assertEquals("refresh1", grants.get(1).get("refresh_token"));
        clock.set(TimeUnit.SECONDS.toNanos(110));
        assertEquals("access3", credentials.token());
        assertEquals("refresh2", grants.get(2).get("refresh_token"));
        clock.set(TimeUnit.SECONDS.toNanos(165));
        assertEquals("access4", credentials.token());
        assertEquals("refresh2", grants.get(3).get("refresh_token")); // Rotation disabled: retain the old token.
        assertEquals(1, browsers.get());
        credentials.close();
        assertThrows(QuackException.class, credentials::token);
        assertEquals(4, grants.size());
        try (ServerSocket ignored = new ServerSocket(config.port(), 1, InetAddress.getByName("127.0.0.1"))) { }
    }

    @Test void concurrentRequestsRefreshOnlyOnce() throws Exception {
        AtomicLong clock = new AtomicLong();
        AtomicInteger exchanges = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        OAuthTestClient client = new OAuthTestClient(request -> {
            int count = exchanges.incrementAndGet();
            if (count == 2) {
                entered.countDown();
                try { assertTrue(release.await(3, TimeUnit.SECONDS)); } catch (InterruptedException e) { throw new AssertionError(e); }
            }
            return new OAuthTestClient.Reply(200, tokens("access" + count, "refresh" + count));
        });
        var credentials = credentials(config(), client, browser(new AtomicInteger()), clock);
        credentials.token();
        clock.set(TimeUnit.SECONDS.toNanos(55));
        var executor = Executors.newFixedThreadPool(8);
        try {
            var futures = new ArrayList<java.util.concurrent.Future<String>>();
            for (int i = 0; i < 8; i++) futures.add(executor.submit(credentials::token));
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            release.countDown();
            for (var future : futures) assertEquals("access2", future.get(3, TimeUnit.SECONDS));
            assertEquals(2, exchanges.get());
        } finally { release.countDown(); executor.shutdownNow(); credentials.close(); }
    }

    @Test void overlappingLoginsKeepTheirOwnCallbackAndPkce() throws Exception {
        var config = config();
        AtomicReference<URI> firstAddress = new AtomicReference<>(), secondAddress = new AtomicReference<>();
        CountDownLatch firstOpened = new CountDownLatch(1), secondEntered = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var first = executor.submit(() -> LoopbackLogin.authorize(config, uri -> {
                firstAddress.set(uri);
                firstOpened.countDown();
            }, Duration.ofSeconds(5)));
            assertTrue(firstOpened.await(3, TimeUnit.SECONDS));
            var second = executor.submit(() -> {
                secondEntered.countDown();
                return LoopbackLogin.authorize(config, uri -> {
                    secondAddress.set(uri);
                    String oldState = LoopbackLogin.parseQuery(firstAddress.get().getRawQuery()).get("state");
                    String state = LoopbackLogin.parseQuery(uri.getRawQuery()).get("state");
                    assertNotEquals(oldState, state);
                    assertEquals(400, callback(config.redirect(), "state=" + oldState + "&code=wrong-login"));
                    assertEquals(200, callback(config.redirect(), "state=" + state + "&code=second-code"));
                }, Duration.ofSeconds(5));
            });
            assertTrue(secondEntered.await(3, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> second.get(150, TimeUnit.MILLISECONDS));
            assertNull(secondAddress.get()); // Do not open a browser until its listener is available.
            String firstState = LoopbackLogin.parseQuery(firstAddress.get().getRawQuery()).get("state");
            assertEquals(200, callback(config.redirect(), "state=" + firstState + "&code=first-code"));
            Map<String, String> firstGrant = first.get(3, TimeUnit.SECONDS);
            Map<String, String> secondGrant = second.get(3, TimeUnit.SECONDS);
            assertEquals("first-code", firstGrant.get("code"));
            assertEquals("second-code", secondGrant.get("code"));
            assertNotEquals(firstGrant.get("code_verifier"), secondGrant.get("code_verifier"));
            for (var attempt : List.of(Map.entry(firstAddress.get(), firstGrant), Map.entry(secondAddress.get(), secondGrant))) {
                assertEquals(LoopbackLogin.parseQuery(attempt.getKey().getRawQuery()).get("code_challenge"),
                        Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256")
                                .digest(attempt.getValue().get("code_verifier").getBytes(StandardCharsets.US_ASCII))));
            }
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS));
        }
        try (ServerSocket ignored = new ServerSocket(config.port(), 1, InetAddress.getByName("127.0.0.1"))) { }
    }

    @Test void failedRefreshDoesNotReuseOldCredentialsOrReopenBrowser() throws Exception {
        AtomicLong clock = new AtomicLong();
        AtomicInteger browsers = new AtomicInteger(), exchanges = new AtomicInteger();
        OAuthTestClient client = new OAuthTestClient(request -> exchanges.incrementAndGet() == 1
                ? new OAuthTestClient.Reply(200, tokens("access1", "refresh1"))
                : new OAuthTestClient.Reply(400, "{\"error\":\"invalid_grant\",\"detail\":\"sensitive-token\"}"));
        var credentials = credentials(config(), client, browser(browsers), clock);
        credentials.token();
        clock.set(TimeUnit.SECONDS.toNanos(55));
        assertFalse(assertThrows(QuackException.class, credentials::token).toString().contains("sensitive-token"));
        assertThrows(QuackException.class, credentials::token);
        assertEquals(2, exchanges.get());
        assertEquals(1, browsers.get());
    }

    @Test void queuedLoginTimeoutAndInterruptionLeaveTheActiveLoginAlone() throws Exception {
        var config = config();
        AtomicReference<URI> address = new AtomicReference<>();
        CountDownLatch opened = new CountDownLatch(1), waiting = new CountDownLatch(1), finished = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicBoolean interrupted = new java.util.concurrent.atomic.AtomicBoolean();
        var executor = Executors.newFixedThreadPool(2);
        try {
            var active = executor.submit(() -> LoopbackLogin.authorize(config, uri -> {
                address.set(uri);
                opened.countDown();
            }, Duration.ofSeconds(5)));
            assertTrue(opened.await(3, TimeUnit.SECONDS));
            assertTrue(assertThrows(QuackException.class, () -> LoopbackLogin.authorize(config,
                    uri -> fail("queued login must not open a browser"), Duration.ofMillis(30)))
                    .getMessage().contains("waiting for another browser sign-in"));
            var queued = executor.submit(() -> {
                try {
                    waiting.countDown();
                    assertThrows(QuackException.class, () -> LoopbackLogin.authorize(config,
                            uri -> fail("interrupted login must not open a browser"), Duration.ofSeconds(5)));
                    interrupted.set(Thread.currentThread().isInterrupted());
                } finally { finished.countDown(); }
            });
            assertTrue(waiting.await(3, TimeUnit.SECONDS));
            queued.cancel(true);
            assertTrue(finished.await(3, TimeUnit.SECONDS));
            assertTrue(interrupted.get());
            assertFalse(active.isDone());
            String state = LoopbackLogin.parseQuery(address.get().getRawQuery()).get("state");
            assertEquals(200, callback(config.redirect(), "state=" + state + "&code=active-code"));
            assertEquals("active-code", active.get(3, TimeUnit.SECONDS).get("code"));
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS));
        }
        try (ServerSocket ignored = new ServerSocket(config.port(), 1, InetAddress.getByName("127.0.0.1"))) { }
    }

    @Test void missingRefreshTokenAndLateTokenResponseFailClosed() throws Exception {
        for (boolean late : List.of(false, true)) {
            AtomicLong clock = new AtomicLong();
            OAuthTestClient client = new OAuthTestClient(request -> {
                if (late) clock.set(TimeUnit.SECONDS.toNanos(61));
                return new OAuthTestClient.Reply(200, tokens("access", late ? "refresh" : null));
            });
            var credentials = credentials(config(), client, browser(new AtomicInteger()), clock);
            assertThrows(QuackException.class, credentials::token);
            assertThrows(QuackException.class, credentials::token);
        }
    }

    @Test void interruptingLoginReleasesTheListener() throws Exception {
        var config = config();
        CountDownLatch started = new CountDownLatch(1), finished = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicBoolean interrupted = new java.util.concurrent.atomic.AtomicBoolean();
        var executor = Executors.newSingleThreadExecutor();
        try {
            var task = executor.submit(() -> {
                try {
                    assertThrows(QuackException.class, () -> LoopbackLogin.authorize(config, uri -> started.countDown(), Duration.ofSeconds(10)));
                    interrupted.set(Thread.currentThread().isInterrupted());
                } finally { finished.countDown(); }
            });
            assertTrue(started.await(3, TimeUnit.SECONDS));
            task.cancel(true);
            assertTrue(finished.await(3, TimeUnit.SECONDS));
            assertTrue(interrupted.get());
            try (ServerSocket ignored = new ServerSocket(config.port(), 1, InetAddress.getByName("127.0.0.1"))) { }
        } finally { executor.shutdownNow(); }
    }

    @Test void callbackRejectsWrongStateDuplicatesPathAndHostWithoutConsumingLogin() throws Exception {
        var config = config();
        Map<String, String> grant = LoopbackLogin.authorize(config, uri -> {
            String state = LoopbackLogin.parseQuery(uri.getRawQuery()).get("state");
            assertEquals(400, callback(config.redirect(), "state=wrong&code=bad"));
            assertEquals(400, callback(config.redirect(), "state=" + state + "&state=" + state + "&code=bad"));
            assertEquals(400, callback(URI.create(config.redirect() + "/extra"), "state=" + state + "&code=bad"));
            assertEquals(400, callback(config.redirect(), "state=" + state + "&code=bad&error=denied"));
            assertEquals(400, callback(URI.create("http://127.0.0.1:" + config.port() + "/quack/callback"), "state=" + state + "&code=bad"));
            assertEquals(200, callback(config.redirect(), "state=" + state + "&code=good"));
        }, Duration.ofSeconds(2));
        assertEquals("good", grant.get("code"));
    }

    @Test void timeoutDenialAndBusyPortCloseTheListener() throws Exception {
        var config = config();
        assertThrows(QuackException.class, () -> LoopbackLogin.authorize(config, uri -> { }, Duration.ofMillis(30)));
        assertThrows(QuackException.class, () -> LoopbackLogin.authorize(config, uri -> {
            String state = LoopbackLogin.parseQuery(uri.getRawQuery()).get("state");
            assertEquals(400, callback(config.redirect(), "state=" + state + "&error=access_denied"));
        }, Duration.ofSeconds(2)));
        try (ServerSocket ignored = new ServerSocket(config.port(), 1, InetAddress.getByName("127.0.0.1"))) {
            assertThrows(QuackException.class, () -> LoopbackLogin.authorize(config, uri -> fail("browser must not open"), Duration.ofSeconds(2)));
        }
    }

    static Properties properties() {
        Properties props = new Properties();
        props.setProperty("authMode", "browser");
        props.setProperty("oauthDomain", "https://login.example");
        props.setProperty("oauthClientId", "client123");
        props.setProperty("oauthScope", "openid email query/read");
        props.setProperty("oauthRedirectPort", "18089");
        props.setProperty("tls", "true");
        return props;
    }

    @Test void configurationRejectsInsecureAndAmbiguousCredentialSources() {
        assertTrue(QuackUri.parse("jdbc:quack://query.example", properties()).token().isEmpty());
        for (String query : List.of("authMode=browser", "oauthDomain=https%3A%2F%2Fevil.example", "tls=false", "token=url-token")) {
            assertThrows(QuackException.class, () -> QuackUri.parse("jdbc:quack://query.example?" + query, properties()));
        }
        for (Map.Entry<String, String> invalid : Map.of("oauthDomain", "http://login.example", "oauthScope", "openid email",
                "oauthRedirectPort", "0", "oauthClientSecret", "secret", "tokenFile", "/must-not-be-read",
                "httpHeader.authorization", "Bearer static").entrySet()) {
            Properties props = properties();
            props.setProperty(invalid.getKey(), invalid.getValue());
            assertThrows(QuackException.class, () -> QuackUri.parse("jdbc:quack://query.example", props));
        }
        Properties missingMode = properties();
        missingMode.remove("authMode");
        assertThrows(QuackException.class, () -> QuackUri.parse("jdbc:quack://query.example", missingMode));
    }
}
