//! Transitional native reference runner.
//!
//! This binary is feature-gated and is never part of the component-factory
//! production launch path.  It remains executable solely as a behavioural
//! oracle while parity evidence is completed.

use std::sync::Arc;

use aiaf_v1::execution::InferenceProviderRegistryEntry;
use aiaf_v1::local_runtime::{
    CreateInferenceTurnRequest, CreateTurnPackageRequest, DriveLlmFactoryProgramRequest,
    ExecuteTurnPackageRequest, LocalRuntimeService, LocalRuntimeWorkspace, RunnerCommand,
    default_console_address, parse_runner_command, serve_local_console,
};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command = parse_runner_command(std::env::args()).map_err(std::io::Error::other)?;
    let workspace = LocalRuntimeWorkspace::default_root()?;
    let service = Arc::new(LocalRuntimeService::new(workspace.clone()).await?);

    match command {
        RunnerCommand::ListScenarios => {
            for scenario in service.list_scenarios().await {
                println!(
                    "{}\t{}\t{:?}\t{:?}\t{}",
                    scenario.scenario_id,
                    scenario.title,
                    scenario.roadmap_class,
                    scenario.maturity,
                    scenario
                        .rollback_kind
                        .map(|kind| format!("{kind:?}"))
                        .unwrap_or_else(|| "None".to_string())
                );
            }
        }
        RunnerCommand::ListInferenceProviders => {
            let registry = service.inference_provider_registry().await?;
            for provider in registry.providers {
                println!(
                    "{}\t{:?}\t{}",
                    provider.provider.provider_id,
                    provider.provider.provider_mode,
                    provider.provider.models.len()
                );
            }
        }
        RunnerCommand::ListLlmDriverProfiles => {
            let ledger = service.llm_factory_program_profile_ledger().await?;
            for profile in ledger.profiles {
                println!(
                    "{}\t{:?}\t{}",
                    profile.profile.llm_factory_program_profile_id,
                    profile.profile.response_schema_family,
                    profile.profile.title
                );
            }
        }
        RunnerCommand::ShowLlmDriverProfile { profile_id } => {
            let view = service
                .llm_factory_program_profile_view(&profile_id)
                .await?;
            println!(
                "llm_factory_program_profile_id: {}",
                view.profile.llm_factory_program_profile_id
            );
            println!("title: {}", view.profile.title);
            println!(
                "response_schema_family: {:?}",
                view.profile.response_schema_family
            );
            println!(
                "max_rendered_prompt_chars: {}",
                view.profile.max_rendered_prompt_chars
            );
            println!(
                "max_continuity_entries: {}",
                view.profile.max_continuity_entries
            );
        }
        RunnerCommand::RegisterInferenceProvider { provider_json_path } => {
            let provider: InferenceProviderRegistryEntry =
                serde_json::from_slice(&std::fs::read(&provider_json_path)?)?;
            let view = service.upsert_inference_provider(provider).await?;
            println!("provider_id: {}", view.provider.provider_id);
            println!("mode: {:?}", view.provider.provider_mode);
            println!("models: {}", view.provider.models.len());
        }
        RunnerCommand::InferTurn { turn_json_path } => {
            let request: CreateInferenceTurnRequest =
                serde_json::from_slice(&std::fs::read(&turn_json_path)?)?;
            let view = service.create_inference_turn(request).await?;
            println!("turn_result_id: {}", view.turn_result.turn_result_id);
            println!("finish_reason: {:?}", view.turn_result.finish_reason);
            println!("provider_ref: {}", view.turn_request.provider_ref);
            println!("model_ref: {}", view.turn_request.model_ref);
            println!("latency_ms: {}", view.usage_record.latency_ms);
            println!(
                "estimated_cost_microunits: {}",
                view.usage_record.estimated_cost_microunits
            );
        }
        RunnerCommand::ListTurnPackages => {
            let ledger = service.turn_package_ledger().await?;
            for turn_package in ledger.turn_packages {
                println!(
                    "{}\t{:?}\t{:?}",
                    turn_package.turn_package.turn_package_id,
                    turn_package.turn_package.role,
                    turn_package.turn_package.response_schema_family
                );
            }
        }
        RunnerCommand::CreateTurnPackage { package_json_path } => {
            let request: CreateTurnPackageRequest =
                serde_json::from_slice(&std::fs::read(&package_json_path)?)?;
            let view = service.create_turn_package(request).await?;
            println!("turn_package_id: {}", view.turn_package.turn_package_id);
            println!("role: {:?}", view.turn_package.role);
            println!(
                "response_schema_family: {:?}",
                view.turn_package.response_schema_family
            );
        }
        RunnerCommand::ListTurnGroundings => {
            let ledger = service.turn_grounding_ledger().await?;
            for turn_grounding in ledger.turn_groundings {
                println!(
                    "{}\t{}\t{}",
                    turn_grounding
                        .turn_grounding_packet
                        .turn_grounding_packet_id,
                    turn_grounding.turn_grounding_packet.turn_package_ref,
                    turn_grounding.continuity_bundle.continuity_bundle_id
                );
            }
        }
        RunnerCommand::ShowTurnGrounding { grounding_ref } => {
            let view = service.turn_grounding_view(&grounding_ref).await?;
            println!(
                "turn_grounding_packet_id: {}",
                view.turn_grounding_packet.turn_grounding_packet_id
            );
            println!(
                "turn_package_ref: {}",
                view.turn_grounding_packet.turn_package_ref
            );
            println!(
                "continuity_bundle_ref: {}",
                view.turn_grounding_packet.continuity_bundle_ref
            );
            println!("retrieval_trace_count: {}", view.retrieval_traces.len());
        }
        RunnerCommand::ListContinuityBundles => {
            let ledger = service.continuity_bundle_ledger().await?;
            for continuity_bundle in ledger.continuity_bundles {
                println!(
                    "{}\t{}\t{}",
                    continuity_bundle.continuity_bundle.continuity_bundle_id,
                    continuity_bundle.continuity_bundle.turn_package_ref,
                    continuity_bundle.continuity_bundle.session_ref
                );
            }
        }
        RunnerCommand::ShowContinuityBundle {
            continuity_bundle_id,
        } => {
            let view = service
                .continuity_bundle_view(&continuity_bundle_id)
                .await?;
            println!(
                "continuity_bundle_id: {}",
                view.continuity_bundle.continuity_bundle_id
            );
            println!(
                "turn_package_ref: {}",
                view.continuity_bundle.turn_package_ref
            );
            println!(
                "pointer_index_ref_count: {}",
                view.continuity_bundle.pointer_index_refs.len()
            );
            println!(
                "lineage_receipt_ref_count: {}",
                view.continuity_bundle.lineage_receipt_refs.len()
            );
        }
        RunnerCommand::RenderTurnPackage { turn_package_id } => {
            let view = service.render_turn_package(&turn_package_id).await?;
            println!("turn_package_id: {}", view.turn_package.turn_package_id);
            println!(
                "prompt_rendering_id: {}",
                view.latest_rendering
                    .as_ref()
                    .map(|record| record.prompt_rendering_id.as_str())
                    .unwrap_or("none")
            );
            println!(
                "rendered_prompt_char_count: {}",
                view.latest_rendering
                    .as_ref()
                    .map(|record| record.rendered_prompt_char_count)
                    .unwrap_or(0)
            );
        }
        RunnerCommand::ExecuteTurnPackage {
            execution_json_path,
        } => {
            let request: ExecuteTurnPackageRequest =
                serde_json::from_slice(&std::fs::read(&execution_json_path)?)?;
            let view = service.execute_turn_package(request).await?;
            println!(
                "parsed_turn_result_id: {}",
                view.parsed_result.parsed_turn_result_id
            );
            println!("status: {:?}", view.parsed_result.status);
            println!(
                "inference_turn_result_id: {}",
                view.inference_turn.turn_result.turn_result_id
            );
            println!(
                "provider_ref: {}",
                view.inference_turn.turn_request.provider_ref
            );
            println!("model_ref: {}", view.inference_turn.turn_request.model_ref);
            println!(
                "latency_ms: {}",
                view.inference_turn.usage_record.latency_ms
            );
            println!(
                "estimated_cost_microunits: {}",
                view.inference_turn.usage_record.estimated_cost_microunits
            );
        }
        RunnerCommand::ListParsedTurnResults => {
            let ledger = service.parsed_turn_result_ledger().await?;
            for parsed_turn_result in ledger.parsed_turn_results {
                println!(
                    "{}\t{:?}\t{}",
                    parsed_turn_result.parsed_result.parsed_turn_result_id,
                    parsed_turn_result.parsed_result.status,
                    parsed_turn_result.turn_package.turn_package_id
                );
            }
        }
        RunnerCommand::ShowTurnGovernance { parsed_result_id } => {
            let view = service.turn_governance_view(&parsed_result_id).await?;
            println!(
                "authority_decision_id: {}",
                view.authority_decision.authority_decision_id
            );
            println!("decision: {:?}", view.authority_decision.decision);
            println!("approval_count: {}", view.approvals.len());
            println!("quarantine_count: {}", view.quarantines.len());
            println!("checkpoint_count: {}", view.checkpoints.len());
        }
        RunnerCommand::ListAuthorityDecisions => {
            let ledger = service.authority_decision_ledger().await?;
            for decision in ledger.decisions {
                println!(
                    "{}\t{:?}\t{}",
                    decision.decision.authority_decision_id,
                    decision.decision.decision,
                    decision.decision.turn_result_ref
                );
            }
        }
        RunnerCommand::ShowAuthorityDecision {
            authority_decision_id,
        } => {
            let view = service
                .authority_decision_view(&authority_decision_id)
                .await?;
            println!(
                "authority_decision_id: {}",
                view.decision.authority_decision_id
            );
            println!("decision: {:?}", view.decision.decision);
            println!("turn_result_ref: {}", view.decision.turn_result_ref);
            println!(
                "delegation_policy_ref: {}",
                view.decision.delegation_policy_ref
            );
        }
        RunnerCommand::ListModelApprovalRequests => {
            let ledger = service.model_approval_request_ledger().await?;
            for approval in ledger.approvals {
                println!(
                    "{}\t{:?}\t{}",
                    approval.approval.model_approval_request_id,
                    approval.approval.approval_request.status,
                    approval.approval.turn_result_ref
                );
            }
        }
        RunnerCommand::ShowModelApprovalRequest {
            model_approval_request_id,
        } => {
            let view = service
                .model_approval_request_view(&model_approval_request_id)
                .await?;
            println!(
                "model_approval_request_id: {}",
                view.approval.model_approval_request_id
            );
            println!(
                "approval_request_id: {}",
                view.approval.approval_request.approval_request_id
            );
            println!("resolution_action: {:?}", view.approval.resolution_action);
            println!("has_pending_action: {}", view.pending_action.is_some());
        }
        RunnerCommand::GrantModelApproval {
            model_approval_request_id,
        } => {
            let view = service
                .grant_model_approval(&model_approval_request_id)
                .await?;
            println!(
                "authority_decision_id: {}",
                view.authority_decision.authority_decision_id
            );
            println!("approval_count: {}", view.approvals.len());
            println!("checkpoint_count: {}", view.checkpoints.len());
        }
        RunnerCommand::DenyModelApproval {
            model_approval_request_id,
        } => {
            let view = service
                .deny_model_approval(&model_approval_request_id)
                .await?;
            println!(
                "authority_decision_id: {}",
                view.authority_decision.authority_decision_id
            );
            println!("approval_count: {}", view.approvals.len());
            println!("checkpoint_count: {}", view.checkpoints.len());
        }
        RunnerCommand::ExpireModelApproval {
            model_approval_request_id,
        } => {
            let view = service
                .expire_model_approval(&model_approval_request_id)
                .await?;
            println!(
                "authority_decision_id: {}",
                view.authority_decision.authority_decision_id
            );
            println!("approval_count: {}", view.approvals.len());
            println!("checkpoint_count: {}", view.checkpoints.len());
        }
        RunnerCommand::EscalateModelApproval {
            model_approval_request_id,
        } => {
            let view = service
                .escalate_model_approval(&model_approval_request_id)
                .await?;
            println!(
                "authority_decision_id: {}",
                view.authority_decision.authority_decision_id
            );
            println!("approval_count: {}", view.approvals.len());
            println!("checkpoint_count: {}", view.checkpoints.len());
        }
        RunnerCommand::ListModelQuarantines => {
            let ledger = service.model_quarantine_ledger().await?;
            for quarantine in ledger.quarantines {
                println!(
                    "{}\t{:?}\t{}",
                    quarantine.quarantine.model_quarantine_id,
                    quarantine.quarantine.reason_class,
                    quarantine.quarantine.affected_turn_result_ref
                );
            }
        }
        RunnerCommand::ShowModelQuarantine {
            model_quarantine_id,
        } => {
            let view = service.model_quarantine_view(&model_quarantine_id).await?;
            println!(
                "model_quarantine_id: {}",
                view.quarantine.model_quarantine_id
            );
            println!("reason_class: {:?}", view.quarantine.reason_class);
            println!(
                "affected_turn_result_ref: {}",
                view.quarantine.affected_turn_result_ref
            );
        }
        RunnerCommand::ListTurnCheckpoints => {
            let ledger = service.turn_checkpoint_ledger().await?;
            for checkpoint in ledger.checkpoints {
                println!(
                    "{}\t{}\t{}",
                    checkpoint.checkpoint.turn_checkpoint_id,
                    checkpoint.checkpoint.resumable,
                    checkpoint.checkpoint.turn_result_ref
                );
            }
        }
        RunnerCommand::ShowTurnCheckpoint { turn_checkpoint_id } => {
            let view = service.turn_checkpoint_view(&turn_checkpoint_id).await?;
            println!("turn_checkpoint_id: {}", view.checkpoint.turn_checkpoint_id);
            println!("turn_result_ref: {}", view.checkpoint.turn_result_ref);
            println!("resumable: {}", view.checkpoint.resumable);
            println!("terminal: {}", view.checkpoint.terminal);
        }
        RunnerCommand::ShowGovernanceHealth => {
            let view = service.governance_health_view().await?;
            println!("total_turns: {}", view.total_turns);
            println!("allow_count: {}", view.allow_count);
            println!("approval_block_count: {}", view.approval_block_count);
            println!("deny_count: {}", view.deny_count);
            println!("quarantine_count: {}", view.quarantine_count);
            println!("fail_count: {}", view.fail_count);
            println!(
                "approval_interrupt_count: {}",
                view.approval_interrupt_count
            );
            println!("quarantine_record_count: {}", view.quarantine_record_count);
            println!(
                "parse_repair_event_count: {}",
                view.parse_repair_event_count
            );
        }
        RunnerCommand::ListTurnMemoryUpdates => {
            let ledger = service.turn_memory_update_ledger().await?;
            for turn_memory_update in ledger.turn_memory_updates {
                println!(
                    "{}\t{}\t{}",
                    turn_memory_update.update.turn_memory_update_id,
                    turn_memory_update.update.turn_result_ref,
                    turn_memory_update.update.output_bundle_ref
                );
            }
        }
        RunnerCommand::ShowTurnMemoryUpdate {
            turn_memory_update_id,
        } => {
            let view = service
                .turn_memory_update_view(&turn_memory_update_id)
                .await?;
            println!(
                "turn_memory_update_id: {}",
                view.update.turn_memory_update_id
            );
            println!("turn_result_ref: {}", view.update.turn_result_ref);
            println!("tool_execution_ref: {}", view.update.tool_execution_ref);
            println!("output_bundle_ref: {}", view.update.output_bundle_ref);
        }
        RunnerCommand::ListModelFactoryCycles => {
            let ledger = service.model_factory_cycle_ledger().await?;
            for cycle in ledger.cycles {
                println!(
                    "{}\t{:?}\t{}",
                    cycle.cycle.model_factory_cycle_id,
                    cycle.cycle.outcome,
                    cycle.cycle.program_instance_ref
                );
            }
        }
        RunnerCommand::ShowModelFactoryCycle { cycle_id } => {
            let view = service.model_factory_cycle_view(&cycle_id).await?;
            println!(
                "model_factory_cycle_id: {}",
                view.cycle.model_factory_cycle_id
            );
            println!("program_instance_ref: {}", view.cycle.program_instance_ref);
            println!("campaign_number: {}", view.cycle.campaign_number);
            println!("outcome: {:?}", view.cycle.outcome);
            println!("turn_package_ref: {}", view.cycle.turn_package_ref);
            println!(
                "parsed_turn_result_ref: {}",
                view.cycle.parsed_turn_result_ref
            );
        }
        RunnerCommand::ListRecursiveLineages => {
            let ledger = service.recursive_lineage_ledger().await?;
            for lineage in ledger.lineages {
                println!(
                    "{}\t{:?}\t{}",
                    lineage.lineage.recursive_lineage_execution_id,
                    lineage.lineage.claim_posture,
                    lineage.lineage.campaign_count
                );
            }
        }
        RunnerCommand::ShowRecursiveLineage { lineage_id } => {
            let view = service.recursive_lineage_view(&lineage_id).await?;
            println!(
                "recursive_lineage_execution_id: {}",
                view.lineage.recursive_lineage_execution_id
            );
            println!(
                "program_instance_ref: {}",
                view.lineage.program_instance_ref
            );
            println!("campaign_count: {}", view.lineage.campaign_count);
            println!("current_depth: {}", view.lineage.current_depth);
            println!("claim_posture: {:?}", view.lineage.claim_posture);
        }
        RunnerCommand::ListProducedWorkerAgents => {
            let ledger = service.produced_worker_agent_ledger().await?;
            for worker in ledger.workers {
                println!(
                    "{}\t{:?}\t{}",
                    worker.worker_card.worker_card_id,
                    worker.worker_card.role_kind,
                    worker
                        .worker_card
                        .production_program_instance_ref
                        .as_deref()
                        .unwrap_or("none")
                );
            }
        }
        RunnerCommand::ShowProducedWorkerAgent { worker_card_id } => {
            let view = service.produced_worker_agent_view(&worker_card_id).await?;
            println!("worker_card_id: {}", view.worker_card.worker_card_id);
            println!("role_kind: {:?}", view.worker_card.role_kind);
            println!("production_mode: {:?}", view.worker_card.production_mode);
            println!(
                "production_program_instance_ref: {}",
                view.worker_card
                    .production_program_instance_ref
                    .as_deref()
                    .unwrap_or("none")
            );
            println!(
                "production_cycle_ref: {}",
                view.worker_card
                    .production_cycle_ref
                    .as_deref()
                    .unwrap_or("none")
            );
        }
        RunnerCommand::ListArchitecturalDependencies => {
            let ledger = service.architectural_dependency_statement_ledger().await?;
            for statement in ledger.statements {
                println!(
                    "{}\t{:?}\t{}",
                    statement.statement.architectural_dependency_statement_id,
                    statement.statement.claim_posture,
                    statement.statement.lineage_ref
                );
            }
        }
        RunnerCommand::ShowArchitecturalDependency { statement_id } => {
            let view = service
                .architectural_dependency_statement_view(&statement_id)
                .await?;
            println!(
                "architectural_dependency_statement_id: {}",
                view.statement.architectural_dependency_statement_id
            );
            println!("lineage_ref: {}", view.statement.lineage_ref);
            println!("claim_posture: {:?}", view.statement.claim_posture);
            println!(
                "claim_boundary_statement: {}",
                view.statement.claim_boundary_statement
            );
        }
        RunnerCommand::ListRecursionClosureDossiers => {
            let ledger = service.recursion_closure_dossier_ledger().await?;
            for dossier in ledger.dossiers {
                println!(
                    "{}\t{:?}\t{}",
                    dossier.dossier.recursion_closure_dossier_id,
                    dossier.dossier.claim_posture,
                    dossier.dossier.lineage_ref
                );
            }
        }
        RunnerCommand::ShowRecursionClosureDossier { dossier_id } => {
            let view = service.recursion_closure_dossier_view(&dossier_id).await?;
            println!(
                "recursion_closure_dossier_id: {}",
                view.dossier.recursion_closure_dossier_id
            );
            println!("lineage_ref: {}", view.dossier.lineage_ref);
            println!("claim_posture: {:?}", view.dossier.claim_posture);
            println!(
                "dependency_statement_ref: {}",
                view.dossier.dependency_statement_ref
            );
        }
        RunnerCommand::ShowRecursiveFactoryHealth => {
            let view = service.recursive_factory_health_view().await?;
            println!(
                "model_driven_cycle_count: {}",
                view.model_driven_cycle_count
            );
            println!(
                "completed_cycle_decision_count: {}",
                view.completed_cycle_decision_count
            );
            println!(
                "produced_worker_agent_count: {}",
                view.produced_worker_agent_count
            );
            println!("adopted_count: {}", view.adopted_count);
            println!("refused_count: {}", view.refused_count);
            println!("rolled_back_count: {}", view.rolled_back_count);
            println!("paused_count: {}", view.paused_count);
            println!("approval_incident_count: {}", view.approval_incident_count);
            println!(
                "quarantine_incident_count: {}",
                view.quarantine_incident_count
            );
            println!("denial_incident_count: {}", view.denial_incident_count);
            println!("failure_incident_count: {}", view.failure_incident_count);
            println!("max_generation_depth: {}", view.max_generation_depth);
        }
        RunnerCommand::ShowToolCatalog => {
            let view = service.tool_catalog_view().await?;
            println!("tool_catalog_id: {}", view.catalog.tool_catalog_id);
            println!("tool_count: {}", view.definitions.len());
            for definition in view.definitions {
                println!("{}\t{:?}", definition.tool_id, definition.family);
            }
        }
        RunnerCommand::ShowTool { tool_id } => {
            let view = service.tool_definition_view(&tool_id).await?;
            println!("tool_id: {}", view.tool_definition.tool_id);
            println!("family: {:?}", view.tool_definition.family);
            println!(
                "internal_service_ref: {}",
                view.tool_definition.internal_service_ref
            );
            println!(
                "required_authority_class: {:?}",
                view.tool_definition.required_authority_class
            );
            println!(
                "default_approval_class: {:?}",
                view.tool_definition.default_approval_class
            );
        }
        RunnerCommand::ShowOperatorOnlySurfaces => {
            let view = service.operator_only_surface_registry().await?;
            for surface in view.operator_only_surfaces {
                println!(
                    "{}\t{}",
                    surface.operator_only_surface_id, surface.internal_service_ref
                );
            }
        }
        RunnerCommand::ExecuteToolIntent {
            parsed_tool_call_intent_id,
        } => {
            let view = service
                .execute_tool_intent(&parsed_tool_call_intent_id)
                .await?;
            println!("tool_execution_id: {}", view.execution.tool_execution_id);
            println!("tool_id: {}", view.execution.tool_id);
            println!("decision: {:?}", view.execution.decision);
        }
        RunnerCommand::ExecuteParsedTurnTools { parsed_result_id } => {
            let view = service.execute_parsed_turn_tools(&parsed_result_id).await?;
            println!(
                "parsed_turn_tool_execution_receipt_id: {}",
                view.receipt.parsed_turn_tool_execution_receipt_id
            );
            println!("terminal_decision: {:?}", view.receipt.terminal_decision);
            println!("tool_execution_count: {}", view.executions.len());
        }
        RunnerCommand::ListToolExecutions => {
            let ledger = service.tool_execution_ledger().await?;
            for tool_execution in ledger.tool_executions {
                println!(
                    "{}\t{:?}\t{}",
                    tool_execution.execution.tool_execution_id,
                    tool_execution.execution.decision,
                    tool_execution.execution.tool_id
                );
            }
        }
        RunnerCommand::Run { scenario_id } => {
            let view = service.run_headless(&scenario_id).await?;
            println!("run_id: {}", view.summary.run_id);
            println!("status: {:?}", view.summary.status);
            println!("bundle: {}", view.summary.bundle_path);
        }
        RunnerCommand::Serve { port } => {
            let address = default_console_address(port);
            println!("AIAF local console listening at http://{}", address);
            serve_local_console(service, address).await?;
        }
        RunnerCommand::Export { run_id } => {
            let path = service.export_run(&run_id).await?;
            println!("{}", path.display());
        }
        RunnerCommand::DriveControlledEvolution => {
            let program = service.drive_controlled_evolution().await?;
            println!("instance_id: {}", program.instance.instance_id);
            println!("state: {:?}", program.instance.program_state);
            println!("generation_depth: {}", program.instance.generation_depth);
            println!("campaign_count: {}", program.instance.campaign_count);
            println!(
                "current_factory_ref: {}",
                program.instance.current_factory_ref
            );
        }
        RunnerCommand::DriveLlmFactoryProgram {
            instance_id,
            driver_json_path,
        } => {
            let request: DriveLlmFactoryProgramRequest =
                serde_json::from_slice(&std::fs::read(&driver_json_path)?)?;
            let program = service
                .drive_llm_factory_program(&instance_id, request)
                .await?;
            println!("instance_id: {}", program.instance.instance_id);
            println!("state: {:?}", program.instance.program_state);
            println!("generation_depth: {}", program.instance.generation_depth);
            println!("campaign_count: {}", program.instance.campaign_count);
            println!(
                "current_factory_ref: {}",
                program.instance.current_factory_ref
            );
            println!(
                "model_factory_cycle_count: {}",
                program.model_factory_cycles.len()
            );
        }
    }

    Ok(())
}
