package com.gizmodata.quack.jdbc.transport;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.gizmodata.quack.jdbc.QuackException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Fixed TLS endpoint; bounded responses, no redirects, no retries and no provider-body logging. */
final class CognitoTokenClient {
    private static final int MAX_RESPONSE = 65536;
    private static final JsonFactory JSON = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(8).maxStringLength(16384).build())
            .build();
    private final URI endpoint;
    private final String clientId;
    private final HttpClient client;

    CognitoTokenClient(URI endpoint, String clientId, HttpClient client) {
        if (!"https".equals(endpoint.getScheme()) || client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new QuackException("OAuth requires HTTPS without redirects");
        }
        this.endpoint = endpoint;
        this.clientId = clientId;
        this.client = client;
    }

    Tokens exchange(Map<String, String> grant) {
        Map<String, String> form = new HashMap<>(grant);
        form.put("client_id", clientId);
        HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(LoopbackLogin.form(form))).build();
        var pending = client.sendAsync(request, ignored -> new LimitedBody());
        try {
            // Bound the complete body, independently of the JDK's request-header timeout behavior.
            HttpResponse<byte[]> response = pending.get(10, TimeUnit.SECONDS);
            if (response.statusCode() != 200) throw new QuackException("Sign-in or refresh was rejected; reconnect to sign in again");
            return parse(response.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new QuackException("Sign-in or refresh was interrupted");
        } catch (IOException | ExecutionException | TimeoutException e) {
            throw new QuackException("Sign-in or refresh could not complete; reconnect to sign in again");
        } finally {
            if (!pending.isDone()) pending.cancel(true);
        }
    }

    static Tokens parse(byte[] data) throws IOException {
        if (data.length > MAX_RESPONSE) throw new IOException();
        String access = null, refresh = null, type = null;
        long lifetime = 0;
        try (JsonParser parser = JSON.createParser(data)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) throw new IOException();
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.FIELD_NAME) throw new IOException();
                String field = parser.currentName();
                JsonToken token = parser.nextToken();
                switch (field) {
                    case "access_token", "refresh_token", "token_type" -> {
                        if (token != JsonToken.VALUE_STRING) throw new IOException();
                        String value = parser.getText();
                        if (value.isEmpty() || value.length() > 16384 || value.chars().anyMatch(c -> c < 33 || c > 126)) throw new IOException();
                        if (field.equals("access_token")) access = value;
                        else if (field.equals("refresh_token")) refresh = value;
                        else type = value;
                    }
                    case "expires_in" -> {
                        if (token != JsonToken.VALUE_NUMBER_INT) throw new IOException();
                        lifetime = parser.getLongValue();
                    }
                    case "error" -> throw new IOException();
                    default -> parser.skipChildren(); // Includes ID tokens, which never grant query access.
                }
            }
            if (parser.nextToken() != null || access == null || !"Bearer".equalsIgnoreCase(type)
                    || lifetime <= 0 || lifetime > 86400) throw new IOException();
        }
        return new Tokens(access, refresh, lifetime);
    }

    record Tokens(String accessToken, String refreshToken, long expiresIn) {
        @Override public String toString() { return "OAuth tokens [redacted]"; }
    }

    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
        private Flow.Subscription subscription;
        private int remaining = MAX_RESPONSE;
        private boolean failed;
        @Override public CompletionStage<byte[]> getBody() { return delegate.getBody(); }
        @Override public void onSubscribe(Flow.Subscription value) { subscription = value; delegate.onSubscribe(value); }
        @Override public void onNext(List<ByteBuffer> buffers) {
            if (failed) return;
            for (ByteBuffer buffer : buffers) {
                if (buffer.remaining() > remaining) {
                    failed = true;
                    subscription.cancel();
                    delegate.onError(new IOException("OAuth response exceeds its size limit"));
                    return;
                }
                remaining -= buffer.remaining();
            }
            delegate.onNext(buffers);
        }
        @Override public void onError(Throwable error) { if (!failed) delegate.onError(error); }
        @Override public void onComplete() { if (!failed) delegate.onComplete(); }
    }
}
