package fr.thomasdelorge.spi.workflow.audit;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.Config;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.Profile;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.delegate.ClientModelLazyDelegate;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.models.workflow.Workflow;
import org.keycloak.models.workflow.WorkflowProvider;
import org.keycloak.models.workflow.WorkflowProviderEvent;
import org.keycloak.models.workflow.WorkflowStep;
import org.keycloak.models.workflow.WorkflowStepRunnerSuccessEvent;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.util.JsonSerialization;

import org.jboss.logging.Logger;

/**
 * Emits {@link org.keycloak.events.admin.AdminEvent AdminEvents} when workflow steps mutate user resources,
 * so realms with admin event persistence can audit automated actions (grant-role, disable-user, etc.).
 * <p>
 * Ignores scheduler noise ({@link WorkflowStepRunnerSuccessEvent}) and only reacts to
 * {@link WorkflowProviderEvent.WorkflowStepExecutedEvent} / {@link WorkflowProviderEvent.WorkflowStepFailedEvent}.
 * <p>
 * Configuration (optional): {@code spi-events-listener--workflow-admin-audit--enabled},
 * {@code spi-events-listener--workflow-admin-audit--step-allowlist} (comma-separated step ids, lowercase).
 */
public final class WorkflowAdminAuditEventListenerFactory implements EventListenerProviderFactory, EnvironmentDependentProviderFactory {

    public static final String ID = "workflow-admin-audit";

    /**
     * Stable synthetic actor IDs (AuthDetails). Chosen as visually obvious "all zeros" UUIDs; avoid
     * {@code 00000000-0000-0000-0000-000000000000} (nil UUID). Unlikely to collide with real entities.
     */
    public static final String SYNTHETIC_ACTOR_USER_ID = "00000000-0000-0000-0000-000000000001";
    public static final String SYNTHETIC_ACTOR_CLIENT_ID = "00000000-0000-0000-0000-000000000002";

    private static final Logger LOG = Logger.getLogger(WorkflowAdminAuditEventListenerFactory.class);

    private static final int MAX_ERROR_MESSAGE_LENGTH = 2000;

    /** Pretty JSON in expandable admin-event details; full structure remains in {@code representation}. */
    private static final int MAX_DETAIL_JSON_LENGTH = 65536;

    private static final int MAX_DETAIL_FIELD_LENGTH = 400;

    private static final Set<String> DEFAULT_USER_STEP_ALLOWLIST = Set.of(
            "grant-role",
            "revoke-role",
            "join-group",
            "leave-group",
            "set-user-attribute",
            "remove-user-attribute",
            "add-required-action",
            "remove-required-action",
            "notify-user",
            "unlink-user",
            "disable-user",
            "delete-user"
    );

    private volatile Set<String> stepAllowlist = DEFAULT_USER_STEP_ALLOWLIST;
    private volatile boolean recordingEnabled = true;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public boolean isGlobal() {
        return true;
    }

    @Override
    public void init(Config.Scope config) {
        recordingEnabled = config.getBoolean("enabled", true);
        String allow = config.get("step-allowlist");
        if (allow == null || allow.isBlank()) {
            stepAllowlist = DEFAULT_USER_STEP_ALLOWLIST;
        } else {
            stepAllowlist = Stream.of(allow.split(","))
                    .map(s -> s.trim().toLowerCase(Locale.ROOT))
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toUnmodifiableSet());
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(this::onProviderEvent);
    }

    private void onProviderEvent(org.keycloak.provider.ProviderEvent event) {
        if (!recordingEnabled) {
            return;
        }
        if (event instanceof WorkflowStepRunnerSuccessEvent) {
            return;
        }
        if (event instanceof WorkflowProviderEvent.WorkflowStepExecutedEvent e) {
            handleStepFinished(e, true, null);
        } else if (event instanceof WorkflowProviderEvent.WorkflowStepFailedEvent e) {
            handleStepFinished(e, false, e.getErrorMessage());
        }
    }

    private void handleStepFinished(WorkflowProviderEvent event, boolean success, String errorMessage) {
        if (event.getResourceType() != org.keycloak.models.workflow.ResourceType.USERS) {
            return;
        }
        String stepId = stepProviderId(event);
        if (stepId == null || !stepAllowlist.contains(stepId.toLowerCase(Locale.ROOT))) {
            return;
        }
        KeycloakSession session = event.getKeycloakSession();
        RealmModel realm = event.getRealm();
        if (session == null || realm == null) {
            return;
        }
        if (!realm.isAdminEventsEnabled()) {
            return;
        }
        try {
            emitAdminEvent(session, realm, event, stepId, success, errorMessage);
        } catch (RuntimeException ex) {
            LOG.warnf(ex, "Failed to record workflow admin audit for realm=%s workflow=%s step=%s resource=%s",
                    realm.getName(), event.getWorkflowName(), stepId, event.getResourceId());
        }
    }

    private static String stepProviderId(WorkflowProviderEvent event) {
        if (event instanceof WorkflowProviderEvent.WorkflowStepExecutedEvent e) {
            return e.getStepProviderId();
        }
        if (event instanceof WorkflowProviderEvent.WorkflowStepFailedEvent e) {
            return e.getStepProviderId();
        }
        return null;
    }

    /** Component id of the workflow step (not the same as step provider / {@code uses} id). */
    private static String stepComponentId(WorkflowProviderEvent event) {
        if (event instanceof WorkflowProviderEvent.WorkflowStepExecutedEvent e) {
            return e.getStepId();
        }
        if (event instanceof WorkflowProviderEvent.WorkflowStepFailedEvent e) {
            return e.getStepId();
        }
        return null;
    }

    private static void emitAdminEvent(KeycloakSession session, RealmModel realm, WorkflowProviderEvent event,
                                       String stepProviderId, boolean success, String errorMessage) {
        RealmModel previousRealm = session.getContext().getRealm();
        // Workflow steps run on the executor pool without an HTTP request. On Quarkus, getConnection()
        // resolves through request-scoped Vertx/RESTEasy and throws ContextNotActiveException.
        ClientConnection connection = InternalClientConnection.INSTANCE;
        session.getContext().setRealm(realm);
        try {
            Map<String, Object> rep = new LinkedHashMap<>();
            rep.put("origin", "workflow-engine");
            rep.put("workflow_id", event.getWorkflowId());
            rep.put("workflow_name", event.getWorkflowName());
            rep.put("execution_id", event.getExecutionId());
            rep.put("resource_type", event.getResourceType().name());
            String targetUserId = event.getResourceId();
            rep.put("target_user_id", targetUserId);
            String targetUsername = resolveTargetUsername(session, realm, targetUserId);
            if (targetUsername != null) {
                rep.put("target_username", targetUsername);
            }
            rep.put("step_success", success);
            if (event instanceof WorkflowProviderEvent.WorkflowStepExecutedEvent e) {
                rep.put("step_id", e.getStepId());
                rep.put("step_provider_id", e.getStepProviderId());
            } else if (event instanceof WorkflowProviderEvent.WorkflowStepFailedEvent e) {
                rep.put("step_id", e.getStepId());
                rep.put("step_provider_id", e.getStepProviderId());
            }
            if (errorMessage != null) {
                rep.put("error_message", truncate(errorMessage, MAX_ERROR_MESSAGE_LENGTH));
            }

            attachDefinitionSnapshots(session, event, rep);

            AdminEventBuilder builder = new AdminEventBuilder(realm, new WorkflowAuditActorAuth(realm), session, connection);
            builder.operation(OperationType.ACTION)
                    .resource(ResourceType.USER)
                    .resourcePath("users", event.getResourceId())
                    .representation(rep);
            addWorkflowAuditDetails(builder, event, stepProviderId, success, errorMessage, rep);
            builder.success();
        } finally {
            session.getContext().setRealm(previousRealm);
        }
    }

    /**
     * Best-effort username for audit readability; omitted when the user is missing or lookup fails.
     */
    private static String resolveTargetUsername(KeycloakSession session, RealmModel realm, String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        try {
            UserModel user = session.users().getUserById(realm, userId);
            if (user == null) {
                return null;
            }
            String username = user.getUsername();
            return (username == null || username.isBlank()) ? null : username;
        } catch (RuntimeException ex) {
            LOG.debugf(ex, "Could not resolve target_username for user id=%s", userId);
            return null;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return null;
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "...";
    }

    /**
     * Loads the persisted workflow and step components and attaches a structural snapshot (workflow-level
     * {@code config} map and per-step {@code step_id}, {@code uses}, {@code config}; JSON keys use snake_case).
     */
    private static void attachDefinitionSnapshots(KeycloakSession session, WorkflowProviderEvent event, Map<String, Object> rep) {
        WorkflowProvider provider = session.getProvider(WorkflowProvider.class);
        if (provider == null) {
            return;
        }
        String stepId = stepComponentId(event);
        if (stepId == null) {
            return;
        }
        try {
            Workflow workflow = provider.getWorkflow(event.getWorkflowId());
            rep.put("workflow_config", multivaluedMapToPlain(workflow.getConfig()));
            WorkflowStep step = workflow.getStepById(stepId);
            if (step != null) {
                rep.put("step_definition", stepToSnapshot(step));
            } else {
                Map<String, Object> missing = new LinkedHashMap<>();
                missing.put("step_id", stepId);
                missing.put("note", "Step component not found when the audit event was recorded");
                rep.put("step_definition", missing);
            }
        } catch (RuntimeException ex) {
            LOG.debugf(ex, "Omitting workflow/step definition snapshot for workflowId=%s stepId=%s",
                    event.getWorkflowId(), stepId);
            rep.put("definition_snapshot_error", truncate(nullToEmpty(ex.getMessage()), MAX_DETAIL_FIELD_LENGTH));
        }
    }

    private static Map<String, Object> stepToSnapshot(WorkflowStep step) {
        Map<String, Object> snap = new LinkedHashMap<>();
        snap.put("step_id", step.getId());
        snap.put("uses", step.getProviderId());
        snap.put("config", multivaluedMapToPlain(step.getConfig()));
        return snap;
    }

    private static Map<String, Object> multivaluedMapToPlain(MultivaluedHashMap<String, String> source) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (source == null || source.isEmpty()) {
            return out;
        }
        for (Map.Entry<String, List<String>> e : source.entrySet()) {
            List<String> vals = e.getValue();
            if (vals == null || vals.isEmpty()) {
                continue;
            }
            if (vals.size() == 1) {
                out.put(e.getKey(), vals.get(0));
            } else {
                out.put(e.getKey(), new ArrayList<>(vals));
            }
        }
        return out;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static void detailPrettyJson(AdminEventBuilder builder, String detailKey, Object value) {
        if (value == null) {
            return;
        }
        try {
            String pretty = JsonSerialization.valueAsPrettyString(value);
            builder.detail(detailKey, truncate(pretty, MAX_DETAIL_JSON_LENGTH));
        } catch (RuntimeException ex) {
            LOG.debugf(ex, "Failed to serialize admin event detail %s", detailKey);
        }
    }

    /**
     * Populates {@link org.keycloak.services.resources.admin.AdminEventBuilder#detail(String, String)} so the
     * Admin Console expandable row shows step/workflow definition JSON (truncated) alongside short fields.
     * <p>
     * Detail keys use snake_case where multi-word names apply. They are appended in reading order: outcome first,
     * then workflow name/id, workflow config JSON, execution id, step provider and component id, step definition JSON,
     * target user id and username, snapshot errors.
     */
    private static void addWorkflowAuditDetails(AdminEventBuilder builder, WorkflowProviderEvent event,
                                                String stepProviderId, boolean success, String errorMessage,
                                                Map<String, Object> representation) {
        String workflow = sanitizeDetailValue(event.getWorkflowName(), MAX_DETAIL_FIELD_LENGTH);
        String step = sanitizeDetailValue(stepProviderId, MAX_DETAIL_FIELD_LENGTH);
        String execution = sanitizeDetailValue(event.getExecutionId(), MAX_DETAIL_FIELD_LENGTH);
        String workflowId = sanitizeDetailValue(stringDetail(representation.get("workflow_id")), MAX_DETAIL_FIELD_LENGTH);
        String stepComponentId = sanitizeDetailValue(stringDetail(representation.get("step_id")), MAX_DETAIL_FIELD_LENGTH);
        String targetUserId = sanitizeDetailValue(stringDetail(representation.get("target_user_id")), MAX_DETAIL_FIELD_LENGTH);
        String targetUsername = sanitizeDetailValue(stringDetail(representation.get("target_username")), MAX_DETAIL_FIELD_LENGTH);

        builder.detail("result", success ? "success" : "failure");
        if (!success && errorMessage != null) {
            String err = sanitizeDetailValue(errorMessage, MAX_ERROR_MESSAGE_LENGTH);
            if (err != null) {
                builder.detail("error", err);
            }
        }
        if (workflow != null) {
            builder.detail("workflow", workflow);
        }
        if (workflowId != null) {
            builder.detail("workflow_id", workflowId);
        }
        detailPrettyJson(builder, "workflow_config", representation.get("workflow_config"));
        if (execution != null) {
            builder.detail("execution", execution);
        }
        if (step != null) {
            builder.detail("step", step);
        }
        if (stepComponentId != null) {
            builder.detail("step_component_id", stepComponentId);
        }
        detailPrettyJson(builder, "step_definition", representation.get("step_definition"));
        if (targetUserId != null) {
            builder.detail("target_user_id", targetUserId);
        }
        if (targetUsername != null) {
            builder.detail("target_username", targetUsername);
        }

        Object snapErr = representation.get("definition_snapshot_error");
        if (snapErr instanceof String s && !s.isBlank()) {
            builder.detail("definition_snapshot_error", s);
        }
    }

    private static String stringDetail(Object value) {
        if (value == null) {
            return null;
        }
        String s = String.valueOf(value).trim();
        return s.isEmpty() ? null : s;
    }

    /** Single-line friendly text for UI detail maps (Admin Console lists key/value pairs). */
    private static String sanitizeDetailValue(String value, int maxLen) {
        if (value == null) {
            return null;
        }
        String singleLine = value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').trim();
        if (singleLine.isEmpty()) {
            return null;
        }
        String collapsed = singleLine.replaceAll(" +", " ");
        return truncate(collapsed, maxLen);
    }

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new WorkflowAdminAuditEventListener();
    }

    @Override
    public void close() {
    }

    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.WORKFLOWS);
    }

    @Override
    public java.util.List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("enabled")
                .type("boolean")
                .defaultValue("true")
                .helpText("When false, no admin events are emitted for workflow steps.")
                .add()
                .property()
                .name("step-allowlist")
                .type("string")
                .helpText("Comma-separated list of workflow step provider IDs to audit (lowercase). Empty uses built-in defaults for user mutations.")
                .add()
                .build();
    }

    /**
     * Synthetic {@link AdminAuth} so {@link AdminEventBuilder} can populate {@link org.keycloak.events.admin.AuthDetails}
     * without a real interactive administrator.
     */
    private static final class WorkflowAuditActorAuth extends AdminAuth {

        WorkflowAuditActorAuth(RealmModel realm) {
            super(realm, null, syntheticActorUser(), syntheticActorClient());
        }

        private static UserModel syntheticActorUser() {
            return new UserModelDelegate(null) {
                @Override
                public String getId() {
                    return SYNTHETIC_ACTOR_USER_ID;
                }
            };
        }

        private static ClientModel syntheticActorClient() {
            return new ClientModelLazyDelegate.WithId(SYNTHETIC_ACTOR_CLIENT_ID, null);
        }
    }

    private enum InternalClientConnection implements ClientConnection {
        INSTANCE;

        @Override
        public String getRemoteAddr() {
            return "0.0.0.0";
        }

        @Override
        public String getRemoteHost() {
            return "workflow-internal";
        }

        @Override
        public int getRemotePort() {
            return 0;
        }

        @Override
        public String getLocalAddr() {
            return "127.0.0.1";
        }

        @Override
        public int getLocalPort() {
            return 0;
        }
    }
}
