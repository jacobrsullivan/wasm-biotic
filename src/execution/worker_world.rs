use crate::execution::capability::{ApprovalClass, CapabilityEnvelope, CapabilityWorld};
use crate::execution::component::{
    ComponentBuildError, ComponentExecutionContext, ComponentExecutionTrace,
    execute_component_export_with_context,
};
use crate::execution::governance::{
    ApprovalRequest, ShellActionDecision, ShellActionDecisionStatus, ShellDenialPacket,
};
use crate::execution::{AuthorityClass, CampaignId, EpochId, SessionId, TaskId, TurnId};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerWorldKind {
    TaskControl,
    ApprovalRequest,
    MemoryRetrieval,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerActionRequest {
    pub action_id: String,
    pub shell_session_id: String,
    pub shell_turn_id: TurnId,
    pub import_name: String,
    pub world_kind: WorkerWorldKind,
    pub capability_world: CapabilityWorld,
    pub operation: String,
    pub resource_scope: String,
    pub required_authority_class: AuthorityClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerActionTrace {
    pub request: WorkerActionRequest,
    pub decision: ShellActionDecision,
    pub effect_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerTurnExecution {
    pub export_name: String,
    pub component_trace: Option<ComponentExecutionTrace>,
    pub action_traces: Vec<WorkerActionTrace>,
    pub approval_request: Option<ApprovalRequest>,
    pub denial_packet: Option<ShellDenialPacket>,
    pub completed_task: bool,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerWorldError {
    UnsupportedCapabilityWorld { world: CapabilityWorld },
    InvokedImportWithoutBinding { import_name: String },
    Component(ComponentBuildError),
}

impl From<ComponentBuildError> for WorkerWorldError {
    fn from(value: ComponentBuildError) -> Self {
        Self::Component(value)
    }
}

impl Display for WorkerWorldError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedCapabilityWorld { world } => {
                write!(
                    f,
                    "worker world is unsupported for capability world {world:?}"
                )
            }
            Self::InvokedImportWithoutBinding { import_name } => {
                write!(f, "invoked import is missing a binding: {import_name}")
            }
            Self::Component(error) => write!(f, "{error}"),
        }
    }
}

impl Error for WorkerWorldError {}

pub fn execute_worker_turn(
    shell_session_id: impl Into<String>,
    shell_turn_id: impl Into<TurnId>,
    campaign_id: impl Into<CampaignId>,
    epoch_id: impl Into<EpochId>,
    session_id: impl Into<SessionId>,
    task_id: impl Into<TaskId>,
    component_bytes: &[u8],
    export_name: impl Into<String>,
    context: &ComponentExecutionContext,
) -> Result<WorkerTurnExecution, WorkerWorldError> {
    let shell_session_id = shell_session_id.into();
    let shell_turn_id = shell_turn_id.into();
    let campaign_id = campaign_id.into();
    let epoch_id = epoch_id.into();
    let session_id = session_id.into();
    let task_id = task_id.into();
    let export_name = export_name.into();

    match execute_component_export_with_context(component_bytes, &export_name, context) {
        Ok(component_trace) => {
            let action_traces = derive_worker_action_traces(
                &shell_session_id,
                &shell_turn_id,
                &campaign_id,
                &epoch_id,
                &session_id,
                &task_id,
                context,
                &component_trace,
            )?;
            let approval_request = action_traces.iter().find_map(|trace| {
                if trace.request.world_kind == WorkerWorldKind::ApprovalRequest {
                    Some(ApprovalRequest::requested(
                        format!("approval-request-{}", trace.request.action_id),
                        campaign_id.clone(),
                        epoch_id.clone(),
                        session_id.clone(),
                        task_id.clone(),
                        trace.request.action_id.clone(),
                        trace.request.resource_scope.clone(),
                        trace.request.required_authority_class.clone(),
                    ))
                } else {
                    None
                }
            });
            let completed_task = action_traces.iter().any(|trace| {
                trace.request.world_kind == WorkerWorldKind::TaskControl
                    && trace.request.operation == "complete-task"
                    && trace.decision.status == ShellActionDecisionStatus::Allowed
            });

            Ok(WorkerTurnExecution {
                export_name,
                component_trace: Some(component_trace),
                action_traces,
                approval_request,
                denial_packet: None,
                completed_task,
                diagnostics: vec![
                    "worker turn executed through the component-native membrane".to_string(),
                ],
            })
        }
        Err(error) => Ok(WorkerTurnExecution {
            export_name: export_name.clone(),
            component_trace: None,
            action_traces: Vec::new(),
            approval_request: None,
            denial_packet: Some(denial_from_component_error(
                &shell_session_id,
                &shell_turn_id,
                &export_name,
                &error,
            )),
            completed_task: false,
            diagnostics: vec![error.to_string()],
        }),
    }
}

pub fn derive_worker_action_traces(
    shell_session_id: &str,
    shell_turn_id: &str,
    campaign_id: &str,
    epoch_id: &str,
    session_id: &str,
    task_id: &str,
    context: &ComponentExecutionContext,
    component_trace: &ComponentExecutionTrace,
) -> Result<Vec<WorkerActionTrace>, WorkerWorldError> {
    let mut traces = Vec::new();
    for (index, import_name) in component_trace.invoked_imports.iter().enumerate() {
        let binding = context
            .import_bindings
            .iter()
            .find(|binding| binding.import_name == *import_name)
            .ok_or_else(|| WorkerWorldError::InvokedImportWithoutBinding {
                import_name: import_name.clone(),
            })?;
        let world_kind = world_kind_for_capability(&binding.world)?;
        let action_id = format!("{shell_turn_id}-action-{index}");
        let request = WorkerActionRequest {
            action_id: action_id.clone(),
            shell_session_id: shell_session_id.to_string(),
            shell_turn_id: shell_turn_id.to_string(),
            import_name: import_name.clone(),
            world_kind,
            capability_world: binding.world.clone(),
            operation: binding.operation.clone(),
            resource_scope: binding.resource_scope.clone(),
            required_authority_class: binding.required_authority_class.clone(),
        };
        let decision = decide_worker_action(
            format!("decision-{action_id}"),
            campaign_id,
            epoch_id,
            session_id,
            task_id,
            &request,
            &context.capability_envelope,
        );
        let effect_ref = match world_kind {
            WorkerWorldKind::TaskControl => Some(format!(
                "task-control:{}:{}",
                request.operation, request.resource_scope
            )),
            WorkerWorldKind::ApprovalRequest => {
                Some(format!("approval-request:{}", request.action_id))
            }
            WorkerWorldKind::MemoryRetrieval => {
                Some(format!("memory-retrieval:{}", request.action_id))
            }
        };
        traces.push(WorkerActionTrace {
            request,
            decision,
            effect_ref,
        });
    }
    Ok(traces)
}

pub fn decide_worker_action(
    decision_id: impl Into<String>,
    _campaign_id: &str,
    _epoch_id: &str,
    _session_id: &str,
    _task_id: &str,
    request: &WorkerActionRequest,
    capability_envelope: &CapabilityEnvelope,
) -> ShellActionDecision {
    if !capability_envelope.grants_world(&request.capability_world) {
        return denied_decision(
            decision_id,
            request,
            None,
            format!(
                "capability world {:?} is missing from envelope {}",
                request.capability_world, capability_envelope.envelope_id
            ),
        );
    }
    if !capability_envelope.scope_allows(&request.resource_scope) {
        return denied_decision(
            decision_id,
            request,
            None,
            format!(
                "resource scope {} is not allowed by envelope {}",
                request.resource_scope, capability_envelope.envelope_id
            ),
        );
    }
    if !capability_envelope.allows_operation(&request.capability_world, &request.operation) {
        return denied_decision(
            decision_id,
            request,
            None,
            format!(
                "operation {:?}::{:?} is not allowed by envelope {}",
                request.capability_world, request.operation, capability_envelope.envelope_id
            ),
        );
    }
    if !capability_envelope.authority_allows(&request.required_authority_class) {
        return denied_decision(
            decision_id,
            request,
            None,
            format!(
                "required authority {:?} exceeds envelope ceiling {:?}",
                request.required_authority_class, capability_envelope.authority_ceiling
            ),
        );
    }

    let approval_class =
        capability_envelope.approval_for(&request.capability_world, &request.operation);
    match approval_class {
        Some(ApprovalClass::AutoAllowed) | Some(ApprovalClass::SupervisorAllowed) => {
            ShellActionDecision {
                decision_id: decision_id.into(),
                shell_session_id: request.shell_session_id.clone(),
                shell_turn_id: request.shell_turn_id.clone(),
                action_ref: request.action_id.clone(),
                status: ShellActionDecisionStatus::Allowed,
                approval_class,
                rationale: "worker action was allowed through the bounded membrane".to_string(),
                diagnostics: Vec::new(),
            }
        }
        Some(ApprovalClass::HumanRequired) => ShellActionDecision {
            decision_id: decision_id.into(),
            shell_session_id: request.shell_session_id.clone(),
            shell_turn_id: request.shell_turn_id.clone(),
            action_ref: request.action_id.clone(),
            status: ShellActionDecisionStatus::ApprovalRequired,
            approval_class,
            rationale: "worker action requires explicit approval before continuing".to_string(),
            diagnostics: Vec::new(),
        },
        Some(ApprovalClass::QuarantineOnExpand) | Some(ApprovalClass::Forbidden) => {
            denied_decision(
                decision_id,
                request,
                approval_class,
                "worker action is denied by the membrane approval class".to_string(),
            )
        }
        None => denied_decision(
            decision_id,
            request,
            None,
            "worker action does not resolve to a valid approval class".to_string(),
        ),
    }
}

pub fn world_kind_for_capability(
    world: &CapabilityWorld,
) -> Result<WorkerWorldKind, WorkerWorldError> {
    match world {
        CapabilityWorld::CampaignControl => Ok(WorkerWorldKind::TaskControl),
        CapabilityWorld::ApprovalGateway => Ok(WorkerWorldKind::ApprovalRequest),
        CapabilityWorld::MemoryAccess => Ok(WorkerWorldKind::MemoryRetrieval),
        _ => Err(WorkerWorldError::UnsupportedCapabilityWorld {
            world: world.clone(),
        }),
    }
}

fn denied_decision(
    decision_id: impl Into<String>,
    request: &WorkerActionRequest,
    approval_class: Option<ApprovalClass>,
    rationale: String,
) -> ShellActionDecision {
    ShellActionDecision {
        decision_id: decision_id.into(),
        shell_session_id: request.shell_session_id.clone(),
        shell_turn_id: request.shell_turn_id.clone(),
        action_ref: request.action_id.clone(),
        status: ShellActionDecisionStatus::Denied,
        approval_class,
        rationale,
        diagnostics: Vec::new(),
    }
}

pub fn denial_from_component_error(
    shell_session_id: &str,
    shell_turn_id: &str,
    action_ref: &str,
    error: &ComponentBuildError,
) -> ShellDenialPacket {
    let status = match error {
        ComponentBuildError::UnsupportedImports(_) => ShellActionDecisionStatus::Unsupported,
        ComponentBuildError::UnboundComponentImport { .. }
        | ComponentBuildError::UnusedImportBinding { .. }
        | ComponentBuildError::DuplicateImportBinding { .. }
        | ComponentBuildError::MalformedImportBinding { .. }
        | ComponentBuildError::ImportCapabilityWorldMissing { .. }
        | ComponentBuildError::ImportResourceScopeNotAllowed { .. }
        | ComponentBuildError::ImportOperationNotAllowed { .. }
        | ComponentBuildError::ImportAuthorityExceedsEnvelope { .. }
        | ComponentBuildError::ImportApprovalBlocked { .. } => ShellActionDecisionStatus::Denied,
        _ => ShellActionDecisionStatus::Unsupported,
    };

    ShellDenialPacket {
        denial_id: format!("shell-denial-{shell_turn_id}"),
        shell_session_id: shell_session_id.to_string(),
        shell_turn_id: shell_turn_id.to_string(),
        action_ref: action_ref.to_string(),
        status,
        rationale: error.to_string(),
        diagnostics: vec![format!("{error:?}")],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ShellActionDecisionStatus, WorkerWorldKind, denial_from_component_error,
        execute_worker_turn, world_kind_for_capability,
    };
    use crate::execution::ComponentBuildError;
    use crate::execution::artifact::GenerationManifest;
    use crate::execution::capability::{
        ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld, CapabilityWorldGrant,
        IsolationProfile,
    };
    use crate::execution::component::{
        ComponentBuildRequest, ComponentExecutionContext, ComponentImportBinding,
        build_component_package,
    };

    fn manifest() -> GenerationManifest {
        GenerationManifest::new(
            "generation-worker-world-test",
            None,
            "package:aiaf/supervisor@test",
            "aiaf-supervisor-v4",
            vec!["src:test".to_string()],
            vec!["policy:test".to_string()],
            vec!["input:test".to_string()],
            "test manifest",
        )
        .unwrap()
    }

    fn approval_component() -> (Vec<u8>, ComponentExecutionContext) {
        let output = build_component_package(ComponentBuildRequest {
            build_id: "build-worker-world-approval".to_string(),
            manifest: manifest(),
            wit_source:
                "world aiaf-supervisor-v4 { import approval-request: func(); export request-approval: func(); }"
                    .to_string(),
            component_source: r#"
                (component
                    (import "approval-request" (func $approval))
                    (core func $approval-core (canon lower (func $approval)))
                    (core module $m
                        (import "" "approval-request" (func $approval))
                        (func (export "request-approval")
                            call $approval))
                    (core instance $i (instantiate $m
                        (with "" (instance
                            (export "approval-request" (func $approval-core))))))
                    (func $request-approval (canon lift (core func $i "request-approval")))
                    (export "request-approval" (func $request-approval)))
            "#.to_string(),
            required_capability_world_refs: vec!["world:test".to_string()],
        })
        .unwrap();

        let context = ComponentExecutionContext {
            capability_envelope: CapabilityEnvelope {
                envelope_id: "envelope-worker-world".to_string(),
                actor_scope: "worker-world-test".to_string(),
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::ApprovalGateway,
                    allowed_operations: vec!["request-approval".to_string()],
                    default_authority_class: AuthorityClass::CampaignControl,
                    default_approval_class: ApprovalClass::AutoAllowed,
                    operation_approval_overrides: Vec::new(),
                }],
                authority_ceiling: AuthorityClass::CampaignControl,
                isolation_profile: IsolationProfile::ArtifactSandbox,
                allowed_resource_scopes: vec!["scope:approval".to_string()],
                approval_overrides: Vec::new(),
                quota_policy: None,
                campaign_scope: None,
                epoch_scope: None,
            },
            import_bindings: vec![ComponentImportBinding {
                import_name: "approval-request".to_string(),
                world: CapabilityWorld::ApprovalGateway,
                operation: "request-approval".to_string(),
                resource_scope: "scope:approval".to_string(),
                required_authority_class: AuthorityClass::CampaignControl,
            }],
        };

        (output.component_bytes, context)
    }

    #[test]
    fn campaign_control_maps_to_task_control_world() {
        assert_eq!(
            world_kind_for_capability(&CapabilityWorld::CampaignControl).unwrap(),
            WorkerWorldKind::TaskControl
        );
    }

    #[test]
    fn executed_approval_import_becomes_approval_request() {
        let (bytes, context) = approval_component();
        let execution = execute_worker_turn(
            "shell-session-1",
            "shell-turn-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            &bytes,
            "request-approval",
            &context,
        )
        .unwrap();

        assert!(execution.denial_packet.is_none());
        assert!(execution.component_trace.is_some());
        assert_eq!(execution.action_traces.len(), 1);
        assert_eq!(
            execution.action_traces[0].request.world_kind,
            WorkerWorldKind::ApprovalRequest
        );
        assert_eq!(
            execution.action_traces[0].decision.status,
            ShellActionDecisionStatus::Allowed
        );
        assert!(execution.approval_request.is_some());
    }

    #[test]
    fn import_approval_block_maps_to_denial_packet() {
        let packet = denial_from_component_error(
            "shell-session-1",
            "shell-turn-1",
            "run",
            &ComponentBuildError::ImportApprovalBlocked {
                import_name: "memory-fetch".to_string(),
                approval_class: "Forbidden".to_string(),
            },
        );

        assert_eq!(packet.status, ShellActionDecisionStatus::Denied);
        assert!(packet.rationale.contains("memory-fetch"));
    }
}
