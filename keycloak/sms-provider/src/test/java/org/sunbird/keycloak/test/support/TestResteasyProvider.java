package org.sunbird.keycloak.test.support;

import org.keycloak.common.util.ResteasyProvider;

/**
 * Minimal no-op ResteasyProvider registered via ServiceLoader for unit tests.
 * Prevents Resteasy.<clinit> from failing with NoSuchElementException when
 * no RESTEasy runtime is present on the test classpath.
 */
public class TestResteasyProvider implements ResteasyProvider {

    @Override
    public <R> R getContextData(Class<R> type) {
        return null;
    }

    @Override
    public void pushDefaultContextObject(Class type, Object instance) {
        // no-op
    }

    @Override
    public void pushContext(Class type, Object instance) {
        // no-op
    }

    @Override
    public void clearContextData() {
        // no-op
    }
}
