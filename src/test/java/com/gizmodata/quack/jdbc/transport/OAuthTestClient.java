package com.gizmodata.quack.jdbc.transport;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import java.util.function.Function;

/** Exercises the real bounded body subscriber without contacting an identity provider. */
final class OAuthTestClient extends HttpClient {
    record Reply(int status, String body) { }
    private final HttpClient defaults = HttpClient.newHttpClient();
    final Function<HttpRequest, Reply> handler;
    boolean canceled;

    OAuthTestClient(Function<HttpRequest, Reply> handler) { this.handler = handler; }

    static Map<String, String> form(HttpRequest request) {
        var subscriber = HttpResponse.BodySubscribers.ofByteArray();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<ByteBuffer>() {
            public void onSubscribe(Flow.Subscription value) { subscriber.onSubscribe(value); }
            public void onNext(ByteBuffer value) { subscriber.onNext(List.of(value)); }
            public void onError(Throwable error) { subscriber.onError(error); }
            public void onComplete() { subscriber.onComplete(); }
        });
        return LoopbackLogin.parseQuery(new String(subscriber.getBody().toCompletableFuture().join(), StandardCharsets.UTF_8));
    }

    @Override public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) throws IOException {
        Reply reply = handler.apply(request);
        HttpHeaders headers = HttpHeaders.of(Map.of("content-type", List.of("application/json")), (a, b) -> true);
        var subscriber = bodyHandler.apply(new HttpResponse.ResponseInfo() {
            public int statusCode() { return reply.status(); }
            public HttpHeaders headers() { return headers; }
            public Version version() { return Version.HTTP_1_1; }
        });
        canceled = false;
        subscriber.onSubscribe(new Flow.Subscription() {
            public void request(long n) { }
            public void cancel() { canceled = true; }
        });
        byte[] data = reply.body().getBytes(StandardCharsets.UTF_8);
        for (int offset = 0; offset < data.length && !canceled; offset += 1024) {
            subscriber.onNext(List.of(ByteBuffer.wrap(data, offset, Math.min(1024, data.length - offset))));
        }
        if (!canceled) subscriber.onComplete();
        final T body;
        try { body = subscriber.getBody().toCompletableFuture().join(); }
        catch (RuntimeException e) { throw new IOException(e); }
        return new HttpResponse<>() {
            public int statusCode() { return reply.status(); }
            public HttpRequest request() { return request; }
            public Optional<HttpResponse<T>> previousResponse() { return Optional.empty(); }
            public HttpHeaders headers() { return headers; }
            public T body() { return body; }
            public Optional<SSLSession> sslSession() { return Optional.empty(); }
            public URI uri() { return request.uri(); }
            public Version version() { return Version.HTTP_1_1; }
        };
    }

    @Override public Optional<CookieHandler> cookieHandler() { return defaults.cookieHandler(); }
    @Override public Optional<Duration> connectTimeout() { return defaults.connectTimeout(); }
    @Override public Redirect followRedirects() { return Redirect.NEVER; }
    @Override public Optional<ProxySelector> proxy() { return defaults.proxy(); }
    @Override public SSLContext sslContext() { return defaults.sslContext(); }
    @Override public SSLParameters sslParameters() { return defaults.sslParameters(); }
    @Override public Optional<Authenticator> authenticator() { return defaults.authenticator(); }
    @Override public Version version() { return defaults.version(); }
    @Override public Optional<Executor> executor() { return defaults.executor(); }
    @Override public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest r, HttpResponse.BodyHandler<T> h) {
        try { return CompletableFuture.completedFuture(send(r, h)); }
        catch (IOException e) { return CompletableFuture.failedFuture(e); }
    }
    @Override public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest r, HttpResponse.BodyHandler<T> h, HttpResponse.PushPromiseHandler<T> p) { throw new UnsupportedOperationException(); }
}
