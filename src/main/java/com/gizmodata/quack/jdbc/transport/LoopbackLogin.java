package com.gizmodata.quack.jdbc.transport;

import com.gizmodata.quack.jdbc.QuackException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/** Short-lived loopback receiver for a public client's authorization-code/PKCE exchange. */
final class LoopbackLogin {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ReentrantLock SIGN_IN = new ReentrantLock(true);

    static Map<String, String> authorize(CognitoCredentials.Config config, Consumer<URI> browser, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        boolean acquired = false;
        try {
            // IDE connections share a callback port, but never share credentials.
            if (!SIGN_IN.tryLock(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS)) {
                throw new QuackException("Timed out waiting for another browser sign-in; reconnect to try again");
            }
            acquired = true;
            if (deadline - System.nanoTime() <= 0) {
                throw new QuackException("Browser sign-in timed out; reconnect to try again");
            }
            return authorizeWithListener(config, browser, deadline);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new QuackException("Browser sign-in was interrupted");
        } finally {
            if (acquired) SIGN_IN.unlock();
        }
    }

    private static Map<String, String> authorizeWithListener(CognitoCredentials.Config config, Consumer<URI> browser,
                                                            long deadline) {
        String state = random();
        String verifier = random();
        String challenge;
        try {
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
        CompletableFuture<String> code = new CompletableFuture<>();
        HttpServer listener;
        try {
            listener = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), config.port()), 1);
        } catch (IOException e) {
            throw new QuackException("Could not open the registered loopback sign-in port; it may already be in use");
        }
        try {
            listener.createContext("/quack/callback", exchange -> receive(exchange, config, state, code));
            listener.start();
            browser.accept(config.domain().resolve("/oauth2/authorize?" + form(Map.of(
                    "response_type", "code", "client_id", config.clientId(), "redirect_uri", config.redirect().toString(),
                    "scope", config.scope(), "state", state, "code_challenge", challenge, "code_challenge_method", "S256"))));
            String value = code.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            return Map.of("grant_type", "authorization_code", "redirect_uri", config.redirect().toString(),
                    "code", value, "code_verifier", verifier);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new QuackException("Browser sign-in was interrupted");
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
            throw new QuackException("Browser sign-in was not completed; reconnect to try again");
        } finally {
            boolean interrupted = Thread.currentThread().isInterrupted();
            listener.stop(0);
            // HttpServer shutdown can clear the interrupted flag while joining its dispatcher.
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private static void receive(HttpExchange exchange, CognitoCredentials.Config config, String state,
                                CompletableFuture<String> code) throws IOException {
        int status = 400;
        String message = "Invalid sign-in callback.";
        String accepted = null;
        boolean denied = false;
        try {
            URI uri = exchange.getRequestURI();
            if (exchange.getRequestMethod().equals("GET") && uri.getRawPath().equals("/quack/callback")
                    && config.redirect().getAuthority().equals(exchange.getRequestHeaders().getFirst("Host"))
                    && uri.getRawQuery() != null && uri.getRawQuery().length() <= 8192 && !code.isDone()) {
                Map<String, String> params = parseQuery(uri.getRawQuery());
                if (state.equals(params.get("state"))) {
                    if (params.containsKey("error") && !params.containsKey("code")) {
                        denied = true;
                        message = "Sign-in was declined. Return to your query tool.";
                    } else if (!params.containsKey("error") && params.get("code") != null && !params.get("code").isBlank()) {
                        accepted = params.get("code");
                        status = 200;
                        message = "Sign-in received. Return to your query tool.";
                    }
                }
            }
        } catch (IllegalArgumentException ignored) {
            // Do not echo codes, state, URLs or provider error descriptions.
        }
        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        try (exchange) {
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
        } finally {
            if (accepted != null) code.complete(accepted);
            if (denied) code.completeExceptionally(new QuackException("Sign-in was declined"));
        }
    }

    static String form(Map<String, String> values) {
        return values.entrySet().stream().map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8)
                + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8)).collect(Collectors.joining("&"));
    }

    static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();
        for (String pair : query.split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length != 2 || result.putIfAbsent(URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                    URLDecoder.decode(parts[1], StandardCharsets.UTF_8)) != null) throw new IllegalArgumentException();
        }
        return result;
    }

    private static String random() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
