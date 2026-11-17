package com.gizmodata.quack.jdbc.transport;

import com.gizmodata.quack.jdbc.QuackException;

import java.awt.Desktop;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/** One connection's credentials. Never persisted, logged, or shared across users. */
final class CognitoCredentials implements AutoCloseable {
    private final Config config;
    private final CognitoTokenClient client;
    private final Consumer<URI> browser;
    private final LongSupplier clock;
    private String accessToken;
    private String refreshToken;
    private long refreshAt;
    private boolean closed;

    static CognitoCredentials from(QuackUri uri) {
        Config config = Config.from(uri);
        if (config == null) return null;
        return new CognitoCredentials(config,
                new CognitoTokenClient(config.domain().resolve("/oauth2/token"), config.clientId(),
                        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
                                .followRedirects(HttpClient.Redirect.NEVER).build()),
                address -> {
                    try {
                        if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                            throw new QuackException("Browser sign-in requires a desktop with a default browser");
                        }
                        Desktop.getDesktop().browse(address);
                    } catch (java.io.IOException e) {
                        throw new QuackException("Could not open the sign-in browser");
                    }
                }, System::nanoTime);
    }

    CognitoCredentials(Config config, CognitoTokenClient client, Consumer<URI> browser, LongSupplier clock) {
        this.config = config;
        this.client = client;
        this.browser = browser;
        this.clock = clock;
    }

    // Heartbeat and query RPCs may race. Serialize only acquisition/refresh, never SQL execution.
    synchronized String token() {
        if (closed) throw new QuackException("Sign-in is no longer available; reconnect the JDBC connection");
        if (accessToken != null && clock.getAsLong() - refreshAt < 0) return accessToken;
        try {
            Map<String, String> grant;
            if (refreshToken == null) {
                grant = LoopbackLogin.authorize(config, browser, Duration.ofMinutes(2));
            } else {
                grant = Map.of("grant_type", "refresh_token", "refresh_token", refreshToken);
            }
            long started = clock.getAsLong();
            CognitoTokenClient.Tokens result = client.exchange(grant);
            long lifetime = result.expiresIn();
            long deadline = started + Duration.ofSeconds(lifetime - Math.min(30, lifetime / 10)).toNanos();
            if (clock.getAsLong() - deadline >= 0) throw new QuackException("Sign-in response arrived after its validity window");
            String replacement = result.refreshToken() != null ? result.refreshToken() : refreshToken;
            if (replacement == null) throw new QuackException("Sign-in did not return a refresh token");
            accessToken = result.accessToken();
            refreshToken = replacement;
            refreshAt = deadline;
            return accessToken;
        } catch (RuntimeException e) {
            close(); // A failed/ambiguous rotation must not reuse the previous refresh token.
            throw e;
        }
    }

    @Override
    public synchronized void close() {
        closed = true;
        accessToken = null;
        refreshToken = null;
    }

    synchronized boolean isClosed() { return closed; }

    record Config(URI domain, String clientId, String scope, int port) {
        static final Set<String> KEYS = Set.of("oauthDomain", "oauthClientId", "oauthScope", "oauthRedirectPort");

        static Config from(QuackUri uri) {
            Map<String, String> props = uri.properties();
            String mode = props.getOrDefault("authMode", "token");
            if (!mode.equals("browser")) {
                if (!mode.equals("token") || props.keySet().stream().anyMatch(k -> k.startsWith("oauth"))) {
                    throw new QuackException("OAuth properties require authMode=browser");
                }
                return null;
            }
            if (!uri.tls()) throw new QuackException("Browser authentication requires tls=true for the query endpoint");
            for (String key : props.keySet()) {
                if (key.startsWith("oauth") && !KEYS.contains(key)) throw new QuackException("Unknown OAuth connection property");
                if (Set.of("token", "password", "tokenEnv", "tokenFile").contains(key) && !props.get(key).isBlank()) {
                    throw new QuackException("Browser authentication cannot be combined with a static token");
                }
            }
            if (uri.token().isPresent() || uri.extraHttpHeaders().keySet().stream().anyMatch("Authorization"::equalsIgnoreCase)) {
                throw new QuackException("Browser authentication owns the Authorization header and handshake token");
            }
            try {
                URI domain = URI.create(required(props, "oauthDomain"));
                if (!"https".equals(domain.getScheme()) || domain.getHost() == null || domain.getUserInfo() != null
                        || domain.getQuery() != null || domain.getFragment() != null
                        || !(domain.getPath().isEmpty() || domain.getPath().equals("/"))) {
                    throw new IllegalArgumentException();
                }
                String clientId = required(props, "oauthClientId");
                if (!clientId.matches("[A-Za-z0-9]{1,128}")) throw new IllegalArgumentException();
                String scope = required(props, "oauthScope");
                if (scope.length() > 1024 || !scope.matches("[\\x21\\x23-\\x5B\\x5D-\\x7E]+( [\\x21\\x23-\\x5B\\x5D-\\x7E]+)*")) {
                    throw new IllegalArgumentException();
                }
                Set<String> scopes = Set.of(scope.split(" "));
                if (!scopes.contains("openid") || !scopes.contains("email") || scopes.size() < 3) throw new IllegalArgumentException();
                int port = Integer.parseInt(required(props, "oauthRedirectPort"));
                if (port < 1024 || port > 65535) throw new IllegalArgumentException();
                return new Config(domain, clientId, scope, port);
            } catch (IllegalArgumentException e) {
                throw new QuackException("Invalid OAuth configuration: use an HTTPS domain, client ID, openid/email/query scopes and registered loopback port");
            }
        }

        private static String required(Map<String, String> props, String name) {
            String value = props.get(name);
            if (value == null || value.isBlank()) throw new IllegalArgumentException();
            return value;
        }

        URI redirect() { return URI.create("http://localhost:" + port + "/quack/callback"); }
    }
}
