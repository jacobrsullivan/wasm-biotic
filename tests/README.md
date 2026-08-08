# Tests

This folder contains deterministic unit and acceptance coverage for the standalone `aiaf-v1` crate.

The current static source inventory contains `462` Rust test attributes: `240` under `src/`, `218` under `tests/acceptance/`, and `4` in the top-level contract integration tests. This is a source inventory, not a claim that all `462` were executed successfully in the latest run.

Only eleven curated scenarios are exposed through `aiaf-v1-runner`. The broader acceptance tree also exercises kernel invariants, bundle validators, HTTP operator flows, and operator/readout workspaces directly in Rust without requiring every path to be a runnable scenario.

The `v3.0` line and the `v3.1` through `v3.6` substrate-completion line now have acceptance coverage under [acceptance](acceptance).

Representative acceptance paths live under [acceptance](acceptance):

- [supervisor_approval_resume_worker_complete.rs](acceptance/supervisor_approval_resume_worker_complete.rs)
- [supervisor_bounded_multi_campaign_contention_control.rs](acceptance/supervisor_bounded_multi_campaign_contention_control.rs)
- [supervisor_campaign_portfolio_budget_continuity.rs](acceptance/supervisor_campaign_portfolio_budget_continuity.rs)
- [supervisor_carried_import_inventory_native_sufficiency.rs](acceptance/supervisor_carried_import_inventory_native_sufficiency.rs)
- [supervisor_capability_audit_reconstruction.rs](acceptance/supervisor_capability_audit_reconstruction.rs)
- [supervisor_continuous_background_program_memory.rs](acceptance/supervisor_continuous_background_program_memory.rs)
- [supervisor_durable_fixed_interface_continuous_self_hosting_program.rs](acceptance/supervisor_durable_fixed_interface_continuous_self_hosting_program.rs)
- [supervisor_evidence_bundle_reconstruction.rs](acceptance/supervisor_evidence_bundle_reconstruction.rs)
- [supervisor_stalled_worker_bounded_recovery.rs](acceptance/supervisor_stalled_worker_bounded_recovery.rs)
- [supervisor_failed_worker_bounded_recovery.rs](acceptance/supervisor_failed_worker_bounded_recovery.rs)
- [supervisor_background_quarantine_rollback_control_loop.rs](acceptance/supervisor_background_quarantine_rollback_control_loop.rs)
- [supervisor_native_memory_governance_substrate.rs](acceptance/supervisor_native_memory_governance_substrate.rs)
- [supervisor_native_orchestration_capability_operation.rs](acceptance/supervisor_native_orchestration_capability_operation.rs)
- [supervisor_integrated_multicycle_stability.rs](acceptance/supervisor_integrated_multicycle_stability.rs)
- [supervisor_native_control_artifact_replay_closure.rs](acceptance/supervisor_native_control_artifact_replay_closure.rs)
- [supervisor_native_service_inventory_closure.rs](acceptance/supervisor_native_service_inventory_closure.rs)
- [supervisor_native_memory_governance_service_continuity.rs](acceptance/supervisor_native_memory_governance_service_continuity.rs)
- [supervisor_native_capability_organelle_approval_transport.rs](acceptance/supervisor_native_capability_organelle_approval_transport.rs)
- [supervisor_native_supervisor_challenger_evaluation.rs](acceptance/supervisor_native_supervisor_challenger_evaluation.rs)
- [supervisor_service_backed_multi_epoch_background_continuity.rs](acceptance/supervisor_service_backed_multi_epoch_background_continuity.rs)
- [supervisor_native_factory_service_challenger_evaluation.rs](acceptance/supervisor_native_factory_service_challenger_evaluation.rs)
- [supervisor_operator_grade_adoption_rollback_rehearsal.rs](acceptance/supervisor_operator_grade_adoption_rollback_rehearsal.rs)
- [supervisor_replay_multiworker_background_native_replacement.rs](acceptance/supervisor_replay_multiworker_background_native_replacement.rs)
- [supervisor_review_canary_release_evidence.rs](acceptance/supervisor_review_canary_release_evidence.rs)
- [supervisor_shadow_challenger_promotion_ready.rs](acceptance/supervisor_shadow_challenger_promotion_ready.rs)
- [supervisor_promote_activate_successor_campaign.rs](acceptance/supervisor_promote_activate_successor_campaign.rs)
- [supervisor_second_cycle_v1_completion.rs](acceptance/supervisor_second_cycle_v1_completion.rs)
- [supervisor_first_bounded_self_hosting_demonstration.rs](acceptance/supervisor_first_bounded_self_hosting_demonstration.rs)
- [supervisor_durable_fixed_interface_self_hosting_loop.rs](acceptance/supervisor_durable_fixed_interface_self_hosting_loop.rs)
- [supervisor_local_runner_scenario_catalog.rs](acceptance/supervisor_local_runner_scenario_catalog.rs)
- [supervisor_local_runner_report_export.rs](acceptance/supervisor_local_runner_report_export.rs)
- [supervisor_run_history_comparison_ledger.rs](acceptance/supervisor_run_history_comparison_ledger.rs)
- [supervisor_observer_agent_capability_view.rs](acceptance/supervisor_observer_agent_capability_view.rs)
- [supervisor_observer_attention_queue_governance.rs](acceptance/supervisor_observer_attention_queue_governance.rs)
- [supervisor_observer_console_run_summary.rs](acceptance/supervisor_observer_console_run_summary.rs)
- [supervisor_evidence_drilldown_review_navigation.rs](acceptance/supervisor_evidence_drilldown_review_navigation.rs)
- [supervisor_factory_portfolio_adoption_workspace.rs](acceptance/supervisor_factory_portfolio_adoption_workspace.rs)
- [supervisor_observer_factory_generation_view.rs](acceptance/supervisor_observer_factory_generation_view.rs)
- [supervisor_observer_front_page_system_overview.rs](acceptance/supervisor_observer_front_page_system_overview.rs)
- [supervisor_operator_runbook_steering_context.rs](acceptance/supervisor_operator_runbook_steering_context.rs)
- [supervisor_observer_progress_tracker_truth.rs](acceptance/supervisor_observer_progress_tracker_truth.rs)
- [supervisor_observer_system_overview_ui.rs](acceptance/supervisor_observer_system_overview_ui.rs)
- [supervisor_campaign_planning_rehearsal_guidance.rs](acceptance/supervisor_campaign_planning_rehearsal_guidance.rs)
- [supervisor_operator_grade_local_factory_cockpit.rs](acceptance/supervisor_operator_grade_local_factory_cockpit.rs)
- [supervisor_approval_resume_via_operator_surface.rs](acceptance/supervisor_approval_resume_via_operator_surface.rs)
- [supervisor_rollback_via_operator_surface.rs](acceptance/supervisor_rollback_via_operator_surface.rs)
- [supervisor_runnable_local_continuous_factory_program.rs](acceptance/supervisor_runnable_local_continuous_factory_program.rs)
- [supervisor_scenario_studio_catalog_governance.rs](acceptance/supervisor_scenario_studio_catalog_governance.rs)
- [supervisor_replay_workspace_checkpoint_branching.rs](acceptance/supervisor_replay_workspace_checkpoint_branching.rs)
- [supervisor_multi_run_diff_and_portfolio_analytics.rs](acceptance/supervisor_multi_run_diff_and_portfolio_analytics.rs)
- [supervisor_operator_context_package_export_import.rs](acceptance/supervisor_operator_context_package_export_import.rs)
- [supervisor_factory_agent_usecase_studio_rehearsal.rs](acceptance/supervisor_factory_agent_usecase_studio_rehearsal.rs)
- [supervisor_scenario_studio_replay_analytics_workspace.rs](acceptance/supervisor_scenario_studio_replay_analytics_workspace.rs)
- [supervisor_scenario_composition_template_inheritance.rs](acceptance/supervisor_scenario_composition_template_inheritance.rs)
- [supervisor_runset_registry_governance.rs](acceptance/supervisor_runset_registry_governance.rs)
- [supervisor_replay_branch_hypothesis_lineage.rs](acceptance/supervisor_replay_branch_hypothesis_lineage.rs)
- [supervisor_approval_branch_rationale_continuity.rs](acceptance/supervisor_approval_branch_rationale_continuity.rs)
- [supervisor_longitudinal_analytics_comparative_review.rs](acceptance/supervisor_longitudinal_analytics_comparative_review.rs)
- [supervisor_campaign_trend_regression_detection.rs](acceptance/supervisor_campaign_trend_regression_detection.rs)
- [supervisor_operator_review_packet_ledger.rs](acceptance/supervisor_operator_review_packet_ledger.rs)
- [supervisor_experiment_ledger_import_export.rs](acceptance/supervisor_experiment_ledger_import_export.rs)
- [supervisor_factory_agent_rehearsal_program_regression_pack.rs](acceptance/supervisor_factory_agent_rehearsal_program_regression_pack.rs)
- [supervisor_bounded_regression_pack_rerun.rs](acceptance/supervisor_bounded_regression_pack_rerun.rs)
- [supervisor_local_experiment_program_workspace.rs](acceptance/supervisor_local_experiment_program_workspace.rs)
- [supervisor_portfolio_board_release_train_governance.rs](acceptance/supervisor_portfolio_board_release_train_governance.rs)
- [supervisor_contract_pressure_v2_boundary_dossier.rs](acceptance/supervisor_contract_pressure_v2_boundary_dossier.rs)
- [supervisor_convergence_scorecard_adoption_evidence.rs](acceptance/supervisor_convergence_scorecard_adoption_evidence.rs)
- [supervisor_final_bounded_self_hosting_campaign_suite.rs](acceptance/supervisor_final_bounded_self_hosting_campaign_suite.rs)
- [supervisor_v2_transition_workspace_export_packet.rs](acceptance/supervisor_v2_transition_workspace_export_packet.rs)
- [supervisor_v1_final_convergence_and_v2_readiness.rs](acceptance/supervisor_v1_final_convergence_and_v2_readiness.rs)
- [supervisor_v2_contract_pressure_normalization.rs](acceptance/supervisor_v2_contract_pressure_normalization.rs)
- [supervisor_v2_effect_class_approval_routing.rs](acceptance/supervisor_v2_effect_class_approval_routing.rs)
- [supervisor_v2_capability_service_closure_gate.rs](acceptance/supervisor_v2_capability_service_closure_gate.rs)
- [supervisor_v2_capability_service_generation_candidate.rs](acceptance/supervisor_v2_capability_service_generation_candidate.rs)
- [supervisor_v2_analytics_review_evidence_linkage.rs](acceptance/supervisor_v2_analytics_review_evidence_linkage.rs)
- [supervisor_v2_contract_change_classification.rs](acceptance/supervisor_v2_contract_change_classification.rs)
- [supervisor_v2_contradiction_lineage_query_services.rs](acceptance/supervisor_v2_contradiction_lineage_query_services.rs)
- [supervisor_v2_compatibility_envelope_coexistence.rs](acceptance/supervisor_v2_compatibility_envelope_coexistence.rs)
- [supervisor_v2_migration_rollback_decision_record.rs](acceptance/supervisor_v2_migration_rollback_decision_record.rs)
- [supervisor_v2_evidence_bundle_review_packet_services.rs](acceptance/supervisor_v2_evidence_bundle_review_packet_services.rs)
- [supervisor_v2_memory_review_lineage_closure_gate.rs](acceptance/supervisor_v2_memory_review_lineage_closure_gate.rs)
- [supervisor_v2_native_carried_service_attestation.rs](acceptance/supervisor_v2_native_carried_service_attestation.rs)
- [supervisor_v2_operator_context_continuity_grounding.rs](acceptance/supervisor_v2_operator_context_continuity_grounding.rs)
- [supervisor_v2_retrieval_profile_query_classes.rs](acceptance/supervisor_v2_retrieval_profile_query_classes.rs)
- [supervisor_v2_service_contract_organelle_handle.rs](acceptance/supervisor_v2_service_contract_organelle_handle.rs)
- [supervisor_v2_contract_map_dossier.rs](acceptance/supervisor_v2_contract_map_dossier.rs)
- [supervisor_v2_contract_foundation_gate.rs](acceptance/supervisor_v2_contract_foundation_gate.rs)
- [supervisor_v2_world_family_brokerage_taxonomy.rs](acceptance/supervisor_v2_world_family_brokerage_taxonomy.rs)

These later `v2.x` labels refer to operator/readout and transition-readiness layers layered over the stable `aiaf_v1::execution` contract. They are not claims that the full Wasm-Biotic northstar is already achieved in the live root package.

The `v3.0` labels refer to the bounded native single-factory self-production proof line that follows the completed first `v2` cycle. The `v3.1` through `v3.6` coverage exercises the root-kernel substrate path for content-addressed generation artifacts, deterministic component packaging, execution-backed validation and comparison, activation and rollback, adopted-generation successor production, and the bounded substrate-completion gate.

The `v1.5` through `v1.9` operational-surface tests validate:

- the shared local scenario registry
- headless run export integrity
- the observer console summary flow
- the front-page system overview and progress tracker truth
- the Factory and Agent operator views
- the attention queue and integrated SystemOverview shell
- durable run history, comparison-ledger, and portfolio-workspace truth
- evidence drill-down, operator runbook continuity, and bounded planning guidance
- scenario-studio governance, replay-branch truth, and structured portfolio analytics
- operator-context package export and import under the same bounded local truth model
- Factory and Agent use-case rehearsal paths and the integrated scenario-studio shell
- governed scenario composition, run-set registries, replay hypotheses, and approval-branch rationale continuity
- longitudinal analytics, review-packet ledgers, and experiment-ledger import and export
- Factory and Agent rehearsal programs plus bounded regression-pack reruns
- and the integrated local experiment-program workspace shell
- the final `v1` portfolio board, release-train governance, contract-pressure dossier, convergence scorecards, final bounded self-hosting suite, and `v2` transition workspace
- the `v2.0` contract-foundation candidate inventory, change-class model, compatibility envelopes, decision ledger, contract map, and integrated contract-foundation gate
- the `v2.1` world taxonomy, service contracts and handles, effect routing, service attestation ledger, capability-service generation candidate, and integrated closure gate
- the `v2.2` retrieval profiles, evidence and review service products, contradiction-aware lineage queries, grounded operator context, evidence-linked analytics, and integrated continuity closure gate
- governed approval and rollback actions through the HTTP operator surface
- the integrated local continuous-factory run path
- the `v2.3` runtime-topology line for coordination domains, scheduler and queue law, replay and recovery surfaces, and bounded contention and fairness
- the `v2.4` governance-release line for protocol records, intervention semantics, release and quarantine law, rollback safety, and operator audit closure
- the `v2.5` integrated-generation line for one operator-readable generation candidate, compatibility rehearsal, operational posture, and comparison dossier
- the `v2.6` native-service generation line for sufficiency gates, adoption rehearsal, closure evidence review, release and rollback symmetry, and operator-reviewable maturity
- the `v2.7` bounded factory-operations line for multi-campaign routing, fairness, pressure, recovery, and one integrated bounded-operations suite
- the `v2.8` self-hosting-transition line for challenger/incumbent comparison, bounded adoption and rollback rehearsal, milestone language, and the first distinct `v2` self-hosting proof
- and the `v2.9` convergence line for final generation scorecards, unresolved pressure summaries, bounded self-hosting phase declaration, next-line handoff export, workspace closure, and the `v3`-pointing readiness gate
- and the integrated local operator cockpit shell
