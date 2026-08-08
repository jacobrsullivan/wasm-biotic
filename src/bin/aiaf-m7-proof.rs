use aiaf_v1::m7_closure::M7ClosureDecision;
use aiaf_v1::m7_operator::{
    M7ActiveSurfaceCaptureInputsV1, M7ActiveSurfaceOutputPathsV1, M7OperatorError,
    accept_independent_review_from_files, accept_source_capture_from_files,
    admit_exact_sources_from_file, assemble_live_provider_source_to_file,
    begin_independent_review_to_file, capture_active_surface_sources_to_files,
    create_manifest_to_file, finalize_dossier_to_file, initialize_dossier, inspect_source_to_file,
    prepare_independent_review_to_files, prepare_source_capture_to_files,
    reopen_and_evaluate_to_file, run_cargo_test_to_file,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run(std::env::args().collect()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), M7OperatorError> {
    if args.len() == 2 && matches!(args[1].as_str(), "help" | "--help" | "-h") {
        println!("{}", usage());
        return Ok(());
    }
    if args.len() < 3 {
        return Err(cli_error(usage()));
    }
    let group = args[1].as_str();
    let action = args[2].as_str();
    let mut flags = Flags::parse(&args[3..])?;
    match (group, action) {
        ("source", "inspect") => {
            let checkout = flags.path("--checkout")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            inspect_source_to_file(&checkout, &output)?;
            println!("source inspection: {}", output.display());
        }
        ("manifest", "create") => {
            let request = flags.path("--request")?;
            let source = flags.path("--source-inspection")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            create_manifest_to_file(&request, &source, &output)?;
            println!("proof-run manifest: {}", output.display());
        }
        ("dossier", "init") => {
            let root = flags.path("--root")?;
            let manifest = flags.path("--manifest")?;
            flags.finish()?;
            initialize_dossier(&root, &manifest)?;
            println!("dossier initialized: {}", root.display());
        }
        ("provider-source", "assemble") => {
            let completed_invocation = flags.path("--completed-invocation")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            assemble_live_provider_source_to_file(&completed_invocation, &output)?;
            println!("live-provider source: {}", output.display());
        }
        ("active-surfaces", "capture") => {
            let inputs = M7ActiveSurfaceCaptureInputsV1 {
                root_readme: flags.path("--readme")?,
                roadmap: flags.path("--roadmap")?,
                base_url: flags.take("--base-url")?,
            };
            let outputs = M7ActiveSurfaceOutputPathsV1 {
                snapshot: flags.path("--snapshot-out")?,
                truth_boundary_source: flags.path("--truth-source-out")?,
                claim_boundary_source: flags.path("--claim-source-out")?,
                publication_policy_source: flags.path("--publication-source-out")?,
            };
            flags.finish()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    M7OperatorError::InvalidInput(format!(
                        "could not construct active-surface capture runtime: {error}"
                    ))
                })?;
            runtime.block_on(capture_active_surface_sources_to_files(&inputs, &outputs))?;
            println!("active-surface snapshot: {}", outputs.snapshot.display());
            println!(
                "M0 truth-boundary source: {}",
                outputs.truth_boundary_source.display()
            );
            println!(
                "M0 claim-boundary source: {}",
                outputs.claim_boundary_source.display()
            );
            println!(
                "M0 publication-policy source: {}",
                outputs.publication_policy_source.display()
            );
        }
        ("evidence", "admit") => {
            let root = flags.path("--root")?;
            let request = flags.path("--request")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            admit_exact_sources_from_file(&root, &request, &output)?;
            println!("evidence admitted: {}", output.display());
        }
        ("transcript", "run") => {
            let checkout = flags.path("--checkout")?;
            let manifest = flags.path("--manifest")?;
            let target_directory = flags.path("--target-dir")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            run_cargo_test_to_file(&checkout, &manifest, &target_directory, &output)?;
            println!("Cargo transcript: {}", output.display());
        }
        ("capture", "prepare") => {
            let root = flags.path("--root")?;
            let transcript = flags.path("--transcript")?;
            let captured_at_ms = flags.u64("--captured-at-ms")?;
            let request_output = flags.path("--request-out")?;
            let preimage_output = flags.path("--preimage-out")?;
            flags.finish()?;
            prepare_source_capture_to_files(
                &root,
                &transcript,
                captured_at_ms,
                &request_output,
                &preimage_output,
            )?;
            println!("source-capture request: {}", request_output.display());
            println!("source-capture preimage: {}", preimage_output.display());
        }
        ("capture", "accept") => {
            let root = flags.path("--root")?;
            let request = flags.path("--request")?;
            let transcript = flags.path("--transcript")?;
            let signature = flags.path("--signature")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            accept_source_capture_from_files(&root, &request, &transcript, &signature, &output)?;
            println!("source capture admitted: {}", output.display());
        }
        ("review", "begin") => {
            let root = flags.path("--root")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            begin_independent_review_to_file(&root, &output)?;
            println!("independent-review request: {}", output.display());
        }
        ("review", "prepare") => {
            let root = flags.path("--root")?;
            let recommendation = flags.decision("--recommendation")?;
            let rationale = flags.path("--rationale")?;
            let independence = flags.path("--independence-statement")?;
            let request_output = flags.path("--request-out")?;
            let preimage_output = flags.path("--preimage-out")?;
            flags.finish()?;
            prepare_independent_review_to_files(
                &root,
                recommendation,
                &rationale,
                &independence,
                &request_output,
                &preimage_output,
            )?;
            println!("review signing request: {}", request_output.display());
            println!("review signing preimage: {}", preimage_output.display());
        }
        ("review", "accept") => {
            let root = flags.path("--root")?;
            let request = flags.path("--request")?;
            let signature = flags.path("--signature")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            accept_independent_review_from_files(&root, &request, &signature, &output)?;
            println!("independent review admitted: {}", output.display());
        }
        ("dossier", "finalize") => {
            let root = flags.path("--root")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            finalize_dossier_to_file(&root, &output)?;
            println!("final bundle: {}", output.display());
        }
        ("dossier", "evaluate") => {
            let root = flags.path("--root")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            let report = reopen_and_evaluate_to_file(&root, &output)?;
            if report.decision == M7ClosureDecision::NotYet || !report.evidence_complete {
                return Err(M7OperatorError::EvaluationNotClosed {
                    decision: report.decision,
                    evidence_complete: report.evidence_complete,
                    report_path: output,
                });
            }
            println!(
                "evaluation report: {} ({:?})",
                output.display(),
                report.decision
            );
        }
        _ => return Err(cli_error(usage())),
    }
    Ok(())
}

struct Flags {
    values: BTreeMap<String, String>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self, M7OperatorError> {
        let mut values = BTreeMap::new();
        let mut index = 0;
        while index < args.len() {
            let name = &args[index];
            if !name.starts_with("--") || name.len() <= 2 {
                return Err(cli_error(format!(
                    "expected a named --flag, found '{name}'"
                )));
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| cli_error(format!("missing value for '{name}'")))?;
            if values.insert(name.clone(), value.clone()).is_some() {
                return Err(cli_error(format!("duplicate flag '{name}'")));
            }
            index += 2;
        }
        Ok(Self { values })
    }

    fn take(&mut self, name: &str) -> Result<String, M7OperatorError> {
        self.values
            .remove(name)
            .ok_or_else(|| cli_error(format!("missing required flag '{name}'")))
    }

    fn path(&mut self, name: &str) -> Result<PathBuf, M7OperatorError> {
        let value = self.take(name)?;
        if value.is_empty() {
            return Err(cli_error(format!("'{name}' cannot be empty")));
        }
        Ok(PathBuf::from(value))
    }

    fn u64(&mut self, name: &str) -> Result<u64, M7OperatorError> {
        let value = self.take(name)?;
        value
            .parse()
            .map_err(|_| cli_error(format!("'{name}' must be an unsigned 64-bit integer")))
    }

    fn decision(&mut self, name: &str) -> Result<M7ClosureDecision, M7OperatorError> {
        match self.take(name)?.as_str() {
            "closed" => Ok(M7ClosureDecision::Closed),
            "closed-with-caveats" | "closed_with_caveats" => {
                Ok(M7ClosureDecision::ClosedWithCaveats)
            }
            "not-yet" | "not_yet" => Ok(M7ClosureDecision::NotYet),
            _ => Err(cli_error(format!(
                "'{name}' must be closed, closed-with-caveats, or not-yet"
            ))),
        }
    }

    fn finish(self) -> Result<(), M7OperatorError> {
        if self.values.is_empty() {
            Ok(())
        } else {
            Err(cli_error(format!(
                "unknown flag(s): {}",
                self.values.keys().cloned().collect::<Vec<_>>().join(", ")
            )))
        }
    }
}

fn cli_error(message: impl Into<String>) -> M7OperatorError {
    M7OperatorError::InvalidInput(message.into())
}

fn usage() -> String {
    "Usage:\n\
  aiaf-m7-proof source inspect --checkout <detached-clean-root> --out <source-inspection.json>\n\
  aiaf-m7-proof manifest create --request <manifest-request.json> --source-inspection <source-inspection.json> --out <manifest.json>\n\
  aiaf-m7-proof dossier init --root <empty-dossier-root> --manifest <manifest.json>\n\
  aiaf-m7-proof provider-source assemble --completed-invocation <completed-provider-invocation.json> --out <live-provider-source.json>\n\
  aiaf-m7-proof active-surfaces capture --readme <README.md> --roadmap <notes/ROADMAP.md> --base-url <http://localhost|127.0.0.1|[::1]:non-default-port> --snapshot-out <active-surfaces.json> --truth-source-out <m0-truth.json> --claim-source-out <m0-claims.json> --publication-source-out <m0-publication.json>\n\
  aiaf-m7-proof evidence admit --root <dossier-root> --request <exact-source-request.json> --out <evidence-link.json>\n\
  aiaf-m7-proof transcript run --checkout <detached-clean-root> --manifest <manifest.json> --target-dir <fresh-empty-absolute-dir> --out <transcript.json>\n\
  aiaf-m7-proof capture prepare --root <dossier-root> --transcript <transcript.json> --captured-at-ms <u64> --request-out <request.json> --preimage-out <preimage.raw>\n\
  aiaf-m7-proof capture accept --root <dossier-root> --request <request.json> --transcript <transcript.json> --signature <ed25519-signature.raw> --out <evidence-link.json>\n\
  aiaf-m7-proof review begin --root <dossier-root> --out <review-request.json>\n\
  aiaf-m7-proof review prepare --root <dossier-root> --recommendation <closed|closed-with-caveats|not-yet> --rationale <text-file> --independence-statement <text-file> --request-out <request.json> --preimage-out <preimage.raw>\n\
  aiaf-m7-proof review accept --root <dossier-root> --request <request.json> --signature <ed25519-signature.raw> --out <evidence-link.json>\n\
  aiaf-m7-proof dossier finalize --root <dossier-root> --out <final-bundle.json>\n\
  aiaf-m7-proof dossier evaluate --root <dossier-root> --out <evaluation.json>\n\n\
All signatures are detached raw 64-byte Ed25519 signatures. This program never accepts private keys and never executes shell command strings."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_exposes_only_the_loopback_active_surface_capture_boundary() {
        let usage = usage();
        for required in [
            "active-surfaces capture",
            "--readme",
            "--roadmap",
            "--base-url",
            "--snapshot-out",
            "--truth-source-out",
            "--claim-source-out",
            "--publication-source-out",
        ] {
            assert!(usage.contains(required), "usage is missing {required}");
        }
        for forbidden in [
            "active-surfaces assemble",
            "--system-overview",
            "--general-audience-home",
            "--north-star-07-closure-review",
            "--remediation-phase-04-final-closure-rereview",
            "--remediation-phase-04-publication-policy",
            "raw-http-body",
        ] {
            assert!(!usage.contains(forbidden), "usage exposes {forbidden}");
        }
        assert!(
            run(vec![
                "aiaf-m7-proof".to_string(),
                "active-surfaces".to_string(),
                "assemble".to_string(),
            ])
            .is_err()
        );
    }

    #[test]
    fn usage_exposes_only_authoritative_runner_transcript_creation() {
        let usage = usage();
        assert!(usage.contains("transcript run"));
        assert!(!usage.contains("transcript create"));
        assert!(
            run(vec![
                "aiaf-m7-proof".to_string(),
                "transcript".to_string(),
                "create".to_string(),
            ])
            .is_err()
        );
    }

    #[test]
    fn usage_requires_the_opaque_completed_provider_invocation() {
        let usage = usage();
        assert!(usage.contains("provider-source assemble"));
        assert!(usage.contains("--completed-invocation"));
        for separable_record in ["--prepared-seed", "--binding", "--execution-receipt"] {
            assert!(
                !usage.contains(separable_record),
                "usage still accepts separable provider authority via {separable_record}"
            );
        }
    }
}
