use crate::execution::{CampaignId, CapabilityEnvelopeId, EpochId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityWorld {
    WorkspaceObserve,
    WorkspaceMutate,
    MemoryAccess,
    WorkerMessaging,
    CampaignControl,
    ApprovalGateway,
    ScheduleTick,
    ServiceOrganelle,
    ReviewPromotion,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthorityClass {
    Observe,
    LocalMutate,
    CampaignControl,
    ExternalInteract,
    SensitiveAccess,
    PromotionControl,
    AutomationControl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalClass {
    AutoAllowed,
    SupervisorAllowed,
    HumanRequired,
    QuarantineOnExpand,
    Forbidden,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationProfile {
    ReadOnlyInspect,
    DisposableWorktree,
    ArtifactSandbox,
    IsolatedServiceNamespace,
    SupervisorExclusive,
}

impl IsolationProfile {
    pub fn satisfies(&self, required: &IsolationProfile) -> bool {
        matches!(
            (self, required),
            (IsolationProfile::SupervisorExclusive, _)
                | (
                    IsolationProfile::DisposableWorktree,
                    IsolationProfile::ReadOnlyInspect
                )
                | (
                    IsolationProfile::ArtifactSandbox,
                    IsolationProfile::ReadOnlyInspect
                )
        ) || self == required
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityOperationApproval {
    pub operation: String,
    pub approval_class: ApprovalClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityWorldGrant {
    pub world: CapabilityWorld,
    pub allowed_operations: Vec<String>,
    pub default_authority_class: AuthorityClass,
    pub default_approval_class: ApprovalClass,
    pub operation_approval_overrides: Vec<CapabilityOperationApproval>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEnvelope {
    pub envelope_id: CapabilityEnvelopeId,
    pub actor_scope: String,
    pub world_grants: Vec<CapabilityWorldGrant>,
    pub authority_ceiling: AuthorityClass,
    pub isolation_profile: IsolationProfile,
    pub allowed_resource_scopes: Vec<String>,
    pub approval_overrides: Vec<String>,
    pub quota_policy: Option<String>,
    pub campaign_scope: Option<CampaignId>,
    pub epoch_scope: Option<EpochId>,
}

impl CapabilityEnvelope {
    pub fn grants_world(&self, required_world: &CapabilityWorld) -> bool {
        self.world_grants
            .iter()
            .any(|grant| &grant.world == required_world)
    }

    pub fn authority_allows(&self, required: &AuthorityClass) -> bool {
        &self.authority_ceiling >= required
    }

    pub fn isolation_allows(&self, required: &IsolationProfile) -> bool {
        self.isolation_profile.satisfies(required)
    }

    pub fn scope_allows(&self, required_scope: &str) -> bool {
        self.allowed_resource_scopes
            .iter()
            .any(|scope| scope == required_scope)
    }

    pub fn matches_scope(&self, campaign_id: &str, epoch_id: &str) -> bool {
        self.campaign_scope
            .as_ref()
            .is_none_or(|candidate| candidate == campaign_id)
            && self
                .epoch_scope
                .as_ref()
                .is_none_or(|candidate| candidate == epoch_id)
    }

    pub fn grant_for(&self, required_world: &CapabilityWorld) -> Option<&CapabilityWorldGrant> {
        self.world_grants
            .iter()
            .find(|grant| &grant.world == required_world)
    }

    pub fn allows_operation(&self, required_world: &CapabilityWorld, operation: &str) -> bool {
        self.grant_for(required_world)
            .map(|grant| {
                grant
                    .allowed_operations
                    .iter()
                    .any(|allowed| allowed == operation)
            })
            .unwrap_or(false)
    }

    pub fn approval_for(
        &self,
        required_world: &CapabilityWorld,
        operation: &str,
    ) -> Option<ApprovalClass> {
        let grant = self.grant_for(required_world)?;
        if !grant
            .allowed_operations
            .iter()
            .any(|allowed| allowed == operation)
        {
            return None;
        }

        grant
            .operation_approval_overrides
            .iter()
            .find(|override_rule| override_rule.operation == operation)
            .map(|override_rule| override_rule.approval_class.clone())
            .or_else(|| Some(grant.default_approval_class.clone()))
    }

    pub fn authority_for(
        &self,
        required_world: &CapabilityWorld,
        operation: &str,
    ) -> Option<AuthorityClass> {
        let grant = self.grant_for(required_world)?;
        if !grant
            .allowed_operations
            .iter()
            .any(|allowed| allowed == operation)
        {
            return None;
        }

        Some(grant.default_authority_class.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityOperationApproval,
        CapabilityWorld, CapabilityWorldGrant, IsolationProfile,
    };

    fn envelope() -> CapabilityEnvelope {
        CapabilityEnvelope {
            envelope_id: "envelope-1".to_string(),
            actor_scope: "worker-1".to_string(),
            world_grants: vec![CapabilityWorldGrant {
                world: CapabilityWorld::WorkspaceObserve,
                allowed_operations: vec!["search".to_string()],
                default_authority_class: AuthorityClass::Observe,
                default_approval_class: ApprovalClass::SupervisorAllowed,
                operation_approval_overrides: vec![CapabilityOperationApproval {
                    operation: "search".to_string(),
                    approval_class: ApprovalClass::HumanRequired,
                }],
            }],
            authority_ceiling: AuthorityClass::LocalMutate,
            isolation_profile: IsolationProfile::ArtifactSandbox,
            allowed_resource_scopes: vec!["workspace-root".to_string()],
            approval_overrides: Vec::new(),
            quota_policy: None,
            campaign_scope: Some("campaign-1".to_string()),
            epoch_scope: Some("epoch-1".to_string()),
        }
    }

    #[test]
    fn envelope_scope_matches_campaign_and_epoch() {
        let envelope = envelope();

        assert!(envelope.matches_scope("campaign-1", "epoch-1"));
        assert!(!envelope.matches_scope("campaign-2", "epoch-1"));
        assert!(!envelope.matches_scope("campaign-1", "epoch-2"));
    }

    #[test]
    fn envelope_reports_authority_for_allowed_operation() {
        let envelope = envelope();

        assert_eq!(
            envelope.authority_for(&CapabilityWorld::WorkspaceObserve, "search"),
            Some(AuthorityClass::Observe)
        );
        assert_eq!(
            envelope.authority_for(&CapabilityWorld::WorkspaceObserve, "open-worktree"),
            None
        );
    }
}
