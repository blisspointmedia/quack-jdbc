package com.gizmodata.quack.jdbc.transport;

import com.gizmodata.quack.jdbc.message.QuackMessage;

/**
 * Transport capable of sending one Quack request and returning its response.
 * V3 sessions may send heartbeat requests concurrently with queries.
 */
public interface QuackTransport extends AutoCloseable {

    QuackMessage send(QuackMessage request);

    @Override
    default void close() { }

    default boolean isClosed() { return false; }
}
