package com.gizmodata.quack.jdbc.sql;

import com.gizmodata.quack.jdbc.QuackException;
import com.gizmodata.quack.jdbc.codec.HugeIntParts;
import com.gizmodata.quack.jdbc.message.*;
import com.gizmodata.quack.jdbc.transport.*;
import org.junit.jupiter.api.Test;

import java.sql.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class QuackMetadataPermissionTest {
    private static final String DENIED = "Function is outside the session capability policy: \"duckdb_functions\"";

    @Test void exactCapabilityDenialReturnsAnEmptyFunctionList() throws Exception {
        Peer peer = new Peer("Permission", DENIED, false);
        try (Connection c = peer.connect(); ResultSet result = c.getMetaData().getFunctions(null,null,"%")) {
            assertFalse(result.next());
            assertEquals(2, peer.sql.size());
            assertFalse(peer.sql.get(1).contains("duckdb_functions"));
            assertFalse(c.isClosed());
        }
    }

    @Test void authenticationAndOtherPermissionErrorsAreNotHidden() throws Exception {
        for (String message : List.of("Session access denied", "Catalog access denied", "Function is outside the session capability policy: \"other_function\"")) {
            Peer peer = new Peer("Permission",message,false);
            try (Connection c = peer.connect()) {
                assertEquals(message,assertThrows(SQLException.class,() -> c.getMetaData().getFunctions(null,null,"%")).getMessage());
                assertEquals(1,peer.sql.size());
            }
        }
    }

    @Test void untypedAndInvalidatingErrorsAreNotHidden() throws Exception {
        for (Peer peer : List.of(new Peer(null,DENIED,false),new Peer("Binder",DENIED,false),new Peer("Permission",DENIED,true))) {
            try (Connection c = peer.connect()) {
                assertThrows(SQLException.class,() -> c.getMetaData().getFunctions(null,null,"%"));
                assertEquals(1,peer.sql.size());
            }
        }
    }

    @Test void transportFailuresAreNotHidden() throws Exception {
        Peer peer = new Peer(null,null,false);
        peer.transportError = true;
        try (Connection c = peer.connect()) {
            assertEquals("fixture transport failed", assertThrows(SQLException.class,() -> c.getMetaData().getFunctions(null,null,"%")).getMessage());
            assertEquals(1,peer.sql.size());
        }
    }

    @Test void unrestrictedFunctionDiscoveryUsesTheOriginalQuery() throws Exception {
        Peer peer = new Peer(null,null,false);
        try (Connection c = peer.connect(); ResultSet result = c.getMetaData().getFunctions("a","main","%")) {
            assertFalse(result.next());
            assertEquals(1,peer.sql.size());
            assertTrue(peer.sql.get(0).contains("FROM duckdb_functions()"));
        }
    }

    private static final class Peer implements QuackTransport {
        final String type, message;
        final boolean invalidate;
        final List<String> sql = new ArrayList<>();
        boolean transportError;
        Peer(String type, String message, boolean invalidate) { this.type=type; this.message=message; this.invalidate=invalidate; }
        Connection connect() { return new QuackConnection(QuackUri.parse("jdbc:quack://example.test"),u -> this); }
        public QuackMessage send(QuackMessage request) {
            if(request instanceof QuackMessage.ConnectionRequest) return new QuackMessage.ConnectionResponse(
                    MessageHeader.of(MessageType.CONNECTION_RESPONSE).withConnectionId("metadata-fixture"),Optional.empty(),Optional.empty(),3,300);
            if(request instanceof QuackMessage.PrepareRequest prepare) {
                sql.add(prepare.sql());
                if(transportError)throw new QuackException("fixture transport failed");
                if(message!=null && sql.size()==1) return new QuackMessage.ErrorResponse(MessageHeader.of(MessageType.ERROR_RESPONSE),message,type,Map.of(),invalidate);
                return new QuackMessage.PrepareResponse(MessageHeader.of(MessageType.PREPARE_RESPONSE),List.of(),List.of(),false,List.of(),prepare.queryUuid());
            }
            return new QuackMessage.SuccessResponse(MessageHeader.of(MessageType.SUCCESS_RESPONSE));
        }
    }
}
