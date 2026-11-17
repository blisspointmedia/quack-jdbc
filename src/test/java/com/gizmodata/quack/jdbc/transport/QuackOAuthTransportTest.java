package com.gizmodata.quack.jdbc.transport;

import com.gizmodata.quack.jdbc.QuackException;
import com.gizmodata.quack.jdbc.codec.HugeIntParts;
import com.gizmodata.quack.jdbc.message.MessageCodec;
import com.gizmodata.quack.jdbc.message.MessageHeader;
import com.gizmodata.quack.jdbc.message.MessageType;
import com.gizmodata.quack.jdbc.message.QuackMessage;
import com.gizmodata.quack.jdbc.sql.QuackSession;
import com.gizmodata.quack.jdbc.sql.QuackConnection;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

class QuackOAuthTransportTest {
    @Test void failedRefreshMarksJdbcConnectionUnusableBeforeSqlIsSent() throws Exception {
        AtomicLong clock = new AtomicLong();
        AtomicInteger exchanges = new AtomicInteger(), requests = new AtomicInteger();
        OAuthTestClient oauth = new OAuthTestClient(request -> exchanges.incrementAndGet() == 1
                ? new OAuthTestClient.Reply(200, CognitoCredentialsTest.tokens("access1", "refresh1"))
                : new OAuthTestClient.Reply(400, "{\"error\":\"invalid_grant\"}"));
        var credentials = CognitoCredentialsTest.credentials(CognitoCredentialsTest.config(), oauth,
                CognitoCredentialsTest.browser(new AtomicInteger()), clock);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/quack", exchange -> {
            requests.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            byte[] body = MessageCodec.encode(new QuackMessage.ConnectionResponse(
                    MessageHeader.of(MessageType.CONNECTION_RESPONSE).withConnectionId("session"), Optional.empty(), Optional.empty(), 3, 300));
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            var uri = QuackUri.parse("jdbc:quack://127.0.0.1:" + server.getAddress().getPort());
            var transport = new QuackHttpTransport(uri.httpUri(), HttpClient.newHttpClient(), Duration.ofSeconds(2), Map.of(), credentials);
            try (var connection = new QuackConnection(uri, ignored -> transport)) {
                clock.set(TimeUnit.SECONDS.toNanos(55));
                try (var statement = connection.createStatement()) {
                    assertEquals("08006", assertThrows(SQLException.class, () -> statement.executeQuery("SELECT 1")).getSQLState());
                }
                assertTrue(connection.isClosed());
                assertFalse(connection.isValid(1));
                assertEquals(1, requests.get());
                assertEquals(2, exchanges.get());
            }
        } finally { server.stop(0); credentials.close(); }
    }

    @Test void handshakeAndRpcHeadersUseCurrentTokenWithoutReplayingDeniedSql() throws Exception {
        AtomicLong clock = new AtomicLong();
        AtomicInteger exchanges = new AtomicInteger();
        OAuthTestClient oauth = new OAuthTestClient(request -> new OAuthTestClient.Reply(200,
                CognitoCredentialsTest.tokens("access" + exchanges.incrementAndGet(), "refresh")));
        var credentials = CognitoCredentialsTest.credentials(CognitoCredentialsTest.config(), oauth,
                CognitoCredentialsTest.browser(new AtomicInteger()), clock);
        List<String> headers = new ArrayList<>();
        List<QuackMessage> messages = new ArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/quack", exchange -> {
            headers.add(exchange.getRequestHeaders().getFirst("Authorization"));
            var message = MessageCodec.decode(exchange.getRequestBody().readAllBytes());
            messages.add(message);
            if (message instanceof QuackMessage.PrepareRequest) {
                exchange.sendResponseHeaders(403, -1);
            } else {
                QuackMessage response = message instanceof QuackMessage.ConnectionRequest
                        ? new QuackMessage.ConnectionResponse(MessageHeader.of(MessageType.CONNECTION_RESPONSE).withConnectionId("same-session"),
                                Optional.empty(), Optional.empty(), 3, 300)
                        : new QuackMessage.SuccessResponse(MessageHeader.of(MessageType.SUCCESS_RESPONSE).withConnectionId("same-session"));
                byte[] body = MessageCodec.encode(response);
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            }
            exchange.close();
        });
        server.start();
        try {
            var transport = new QuackHttpTransport(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/quack"),
                    HttpClient.newHttpClient(), Duration.ofSeconds(2), Map.of(), credentials);
            var session = QuackSession.connect(QuackUri.parse("jdbc:quack://fixture.invalid"), transport);
            assertEquals("same-session", session.connectionId());
            assertEquals(Optional.of("access1"), ((QuackMessage.ConnectionRequest) messages.get(0)).authString());
            assertEquals("Bearer access1", headers.get(0));
            clock.set(TimeUnit.SECONDS.toNanos(55));
            transport.send(new QuackMessage.FetchRequest(MessageHeader.of(MessageType.FETCH_REQUEST).withConnectionId(session.connectionId()), new HugeIntParts(1, 2), 1, 0));
            assertEquals("Bearer access2", headers.get(1));
            assertEquals(Optional.of("same-session"), messages.get(1).header().connectionId());
            assertThrows(QuackException.class, () -> session.cursor("SELECT 1"));
            assertEquals(3, messages.size());
            assertEquals(2, exchanges.get());
            session.close();
            assertInstanceOf(QuackMessage.DisconnectMessage.class, messages.get(3));
            assertEquals("Bearer access2", headers.get(3));
            assertThrows(QuackException.class, credentials::token);
        } finally { server.stop(0); credentials.close(); }
    }
}
