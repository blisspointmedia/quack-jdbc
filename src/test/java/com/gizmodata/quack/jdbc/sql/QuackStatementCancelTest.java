package com.gizmodata.quack.jdbc.sql;

import com.gizmodata.quack.jdbc.codec.HugeIntParts;
import com.gizmodata.quack.jdbc.message.*;
import com.gizmodata.quack.jdbc.transport.QuackTransport;
import com.gizmodata.quack.jdbc.transport.QuackUri;
import com.gizmodata.quack.jdbc.type.LogicalType;
import com.gizmodata.quack.jdbc.type.LogicalTypeId;
import org.junit.jupiter.api.Test;

import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class QuackStatementCancelTest {
    private static final LogicalType INTEGER = LogicalType.of(LogicalTypeId.INTEGER);
    private static final DataChunk ROW = new DataChunk(1, List.of(INTEGER),
            List.of(new DecodedVector.IntVec(INTEGER, new int[]{42}, null)));

    @Test void cancellationDuringPreparePublishesNoResultAndRetainsCause() throws Exception {
        Peer peer = new Peer("prepare");
        peer.failAfterRelease = true;
        try (QuackConnection c = peer.connect(); Statement s = c.createStatement()) {
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                Future<SQLException> result = worker.submit(() -> assertThrows(SQLException.class, () -> s.executeQuery("SELECT slow")));
                assertTrue(peer.entered.await(3, TimeUnit.SECONDS));
                s.cancel();
                SQLException error = result.get(3, TimeUnit.SECONDS);
                assertEquals("57014", error.getSQLState());
                assertNotNull(error.getCause().getCause());
                assertEquals(peer.active, peer.cancels.get(0));
            } finally { peer.release.countDown(); worker.shutdownNow(); }
        }
    }

    @Test void cancellationInterruptsInitialFetchBeforeExecuteReturns() throws Exception {
        Peer peer = new Peer("fetch");
        try (QuackConnection c = peer.connect(); Statement s = c.createStatement()) {
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                Future<SQLException> result = worker.submit(() -> assertThrows(SQLException.class,
                        () -> s.executeQuery("SELECT slow")));
                assertTrue(peer.entered.await(3, TimeUnit.SECONDS));
                s.cancel();
                assertEquals("57014", result.get(3, TimeUnit.SECONDS).getSQLState());
                assertFalse(peer.cancels.isEmpty());
            } finally { peer.release.countDown(); worker.shutdownNow(); }
        }
    }

    @Test void cancellationCanPassALaterFetch() throws Exception {
        Peer peer = new Peer("later-fetch");
        try (QuackConnection c = peer.connect(); Statement s = c.createStatement();
             ResultSet rows = s.executeQuery("SELECT slow")) {
            assertTrue(rows.next());
            assertEquals(42, rows.getInt(1));
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                Future<SQLException> result = worker.submit(() -> assertThrows(SQLException.class, rows::next));
                assertTrue(peer.entered.await(3, TimeUnit.SECONDS));
                s.cancel();
                assertEquals("57014", result.get(3, TimeUnit.SECONDS).getSQLState());
                assertEquals(peer.active, peer.cancels.get(0));
            } finally { peer.release.countDown(); worker.shutdownNow(); }
        }
    }

    @Test void earlyCancelIsRepeatedAfterPrepareRegistersTheQuery() throws Exception {
        Peer peer = new Peer("prepare");
        peer.rejectEarly = true;
        try (QuackConnection c = peer.connect(); Statement s = c.createStatement()) {
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                Future<SQLException> result = worker.submit(() -> assertThrows(SQLException.class, () -> s.executeQuery("SELECT slow")));
                assertTrue(peer.entered.await(3, TimeUnit.SECONDS));
                s.cancel();
                assertEquals(1, peer.cancels.size());
                peer.release.countDown();
                assertEquals("57014", result.get(3, TimeUnit.SECONDS).getSQLState());
                assertEquals(2, peer.cancels.size());
                assertEquals(peer.cancels.get(0), peer.cancels.get(1));
                assertEquals(1, peer.prepares.get());
            } finally { peer.release.countDown(); worker.shutdownNow(); }
        }
    }

    @Test void cancelBeforeDispatchSendsNoPrepare() {
        Peer peer = new Peer("none");
        try (QuackConnection c = peer.connect()) {
            QuackSession.Execution execution = c.session().newExecution();
            execution.cancel();
            assertThrows(QuackSession.Cancelled.class, () -> c.session().cursor("SELECT never", execution));
            assertEquals(0, peer.prepares.get());
        }
    }

    @Test void staleStatementAndLateResultCloseCannotCancelTheNewStatement() throws Exception {
        Peer peer = new Peer("none");
        try (QuackConnection c = peer.connect(); Statement old = c.createStatement(); Statement next = c.createStatement()) {
            ResultSet first = old.executeQuery("SELECT first");
            HugeIntParts firstId = peer.active;
            ResultSet second = next.executeQuery("SELECT second");
            HugeIntParts secondId = peer.active;
            assertNotEquals(firstId, secondId);
            old.cancel();
            assertTrue(peer.cancels.isEmpty()); // Upstream buffered the first result before starting the second.
            first.close();
            assertTrue(second.next());
            assertEquals(42, second.getInt(1));
            next.cancel();
            assertEquals(secondId, peer.cancels.get(peer.cancels.size()-1));
            assertEquals("57014", assertThrows(SQLException.class, second::next).getSQLState());
            assertTrue(peer.cancels.stream().noneMatch(id -> id.equals(new HugeIntParts(0,0))));
        }
    }

    @Test void completedAndIdleStatementsDoNotCancelOtherWork() throws Exception {
        Peer peer = new Peer("none");
        try (QuackConnection c = peer.connect(); Statement old = c.createStatement(); Statement next = c.createStatement()) {
            old.cancel();
            try (ResultSet r = old.executeQuery("SELECT done")) { assertTrue(r.next()); assertFalse(r.next()); }
            next.executeQuery("SELECT active");
            old.cancel();
            assertTrue(peer.cancels.isEmpty());
            old.close();
            assertThrows(SQLException.class, old::cancel);
        }
    }

    @Test void closeCanCancelAnOutstandingPrepare() throws Exception {
        Peer peer = new Peer("prepare");
        try (QuackConnection c = peer.connect()) {
            Statement s = c.createStatement();
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                Future<SQLException> result = worker.submit(() -> assertThrows(SQLException.class, () -> s.executeQuery("SELECT slow")));
                assertTrue(peer.entered.await(3, TimeUnit.SECONDS));
                s.close();
                assertEquals("57014", result.get(3, TimeUnit.SECONDS).getSQLState());
                assertTrue(s.isClosed());
            } finally { peer.release.countDown(); worker.shutdownNow(); }
        }
    }

    @Test void delayedCancelCannotAffectANewerStatement() throws Exception {
        Peer peer = new Peer("cancel");
        try (QuackConnection c = peer.connect(); Statement old = c.createStatement(); Statement next = c.createStatement()) {
            ResultSet first = old.executeQuery("SELECT first");
            HugeIntParts firstId = peer.active;
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                Future<?> cancelling = worker.submit(() -> { old.cancel(); return null; });
                assertTrue(peer.entered.await(3, TimeUnit.SECONDS));
                ResultSet second = next.executeQuery("SELECT second");
                HugeIntParts secondId = peer.active;
                peer.release.countDown();
                cancelling.get(3, TimeUnit.SECONDS);
                first.close();
                assertEquals(List.of(firstId), peer.cancels);
                assertTrue(second.next());
                assertEquals(42, second.getInt(1));
                second.close();
                assertEquals(secondId, peer.cancels.get(peer.cancels.size() - 1));
            } finally { peer.release.countDown(); worker.shutdownNow(); }
        }
    }

    @Test void sameStatementCanRunAgainAfterCancellation() throws Exception {
        Peer peer = new Peer("none");
        try (QuackConnection c = peer.connect(); Statement s = c.createStatement()) {
            ResultSet first = s.executeQuery("SELECT first");
            HugeIntParts firstId = peer.active;
            s.cancel();
            assertEquals("57014", assertThrows(SQLException.class, first::next).getSQLState());
            try (ResultSet second = s.executeQuery("SELECT second")) {
                assertNotEquals(firstId, peer.active);
                assertTrue(second.next());
                assertEquals(42, second.getInt(1));
                assertFalse(second.next());
            }
        }
    }

    @Test void cancelPropagatesServerFailuresAndStillStopsLocalDelivery() throws Exception {
        Peer peer = new Peer("none");
        peer.cancelError = "Cancellation rejected by fixture policy";
        try (QuackConnection c = peer.connect(); Statement s = c.createStatement()) {
            ResultSet result = s.executeQuery("SELECT first");
            SQLException failure = assertThrows(SQLException.class, s::cancel);
            assertEquals(peer.cancelError, failure.getMessage());
            assertNotNull(failure.getCause());
            assertEquals("57014", assertThrows(SQLException.class, result::next).getSQLState());
        }
    }

    @Test void oldProtocolIsRejectedBeforeSql() {
        Peer peer = new Peer("none");
        peer.version = 1;
        assertThrows(com.gizmodata.quack.jdbc.QuackProtocolException.class, peer::connect);
        assertEquals(0, peer.prepares.get());
    }

    private static final class Peer implements QuackTransport {
        final String blocked;
        final CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        final List<HugeIntParts> cancels = new CopyOnWriteArrayList<>();
        final AtomicInteger prepares = new AtomicInteger();
        volatile HugeIntParts active;
        boolean rejectEarly, failAfterRelease;
        String cancelError;
        int version = 3;
        Peer(String blocked) { this.blocked = blocked; }
        QuackConnection connect() {
            return new QuackConnection(QuackUri.parse("jdbc:quack://example.test?protocolVersion="+version), uri -> this);
        }
        void await() {
            entered.countDown();
            try { assertTrue(release.await(5,TimeUnit.SECONDS)); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
        }
        public QuackMessage send(QuackMessage request) {
            if (request instanceof QuackMessage.ConnectionRequest connect) {
                return new QuackMessage.ConnectionResponse(MessageHeader.of(MessageType.CONNECTION_RESPONSE).withConnectionId("fixture"),
                        Optional.empty(),Optional.empty(),version,connect.heartbeatTimeoutSeconds());
            }
            if (request instanceof QuackMessage.PrepareRequest prepare) {
                prepares.incrementAndGet();
                active=prepare.queryUuid();
                if (blocked.equals("prepare")) await();
                if (failAfterRelease) return new QuackMessage.ErrorResponse(MessageHeader.of(MessageType.ERROR_RESPONSE),"Interrupted by test cancel","Interrupt",Map.of(),false);
                return new QuackMessage.PrepareResponse(MessageHeader.of(MessageType.PREPARE_RESPONSE),List.of(INTEGER),List.of("value"),
                        version==3,blocked.equals("fetch")?List.of():List.of(ROW),active);
            }
            if (request instanceof QuackMessage.CancelRequest cancel) {
                cancels.add(cancel.queryUuid());
                if (blocked.equals("cancel")) await();
                if (cancelError != null) return new QuackMessage.ErrorResponse(MessageHeader.of(MessageType.ERROR_RESPONSE), cancelError,"Permission",Map.of(),false);
                if (!cancel.queryUuid().equals(active) || (rejectEarly && release.getCount()!=0)) {
                    return new QuackMessage.ErrorResponse(MessageHeader.of(MessageType.ERROR_RESPONSE),"Attempted to cancel a different query","Invalid Input",Map.of(),false);
                }
                release.countDown();
            }
            if (request instanceof QuackMessage.FetchRequest) {
                if (blocked.equals("fetch") || blocked.equals("later-fetch")) await();
                return new QuackMessage.FetchResponse(MessageHeader.of(MessageType.FETCH_RESPONSE),List.of(),OptionalLong.of(0L),OptionalLong.empty());
            }
            return new QuackMessage.SuccessResponse(MessageHeader.of(MessageType.SUCCESS_RESPONSE));
        }
    }
}
