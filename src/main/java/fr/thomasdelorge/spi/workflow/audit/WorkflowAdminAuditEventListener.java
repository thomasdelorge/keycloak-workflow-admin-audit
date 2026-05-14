package fr.thomasdelorge.spi.workflow.audit;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;

/**
 * No-op listener: workflow audit is handled via {@link WorkflowAdminAuditEventListenerFactory#postInit}
 * registered {@link org.keycloak.provider.ProviderEvent} consumer.
 */
public final class WorkflowAdminAuditEventListener implements EventListenerProvider {

    @Override
    public void onEvent(Event event) {
        // intentionally empty
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // intentionally empty
    }

    @Override
    public void close() {
    }
}
