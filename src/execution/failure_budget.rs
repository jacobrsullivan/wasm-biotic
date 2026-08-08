use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryClass {
    TransientModel,
    TransientCapability,
    TransientWorker,
    ApprovalTimeoutRetryable,
    StructuralNonRetryable,
    PolicyNonRetryable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopCondition {
    ExplicitTaskCompletion,
    OperatorHalt,
    GovernanceHardStop,
    StructuralValidationFailure,
    FailureBudgetExhausted,
    NoProgressCeilingReached,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureBudget {
    pub session_failures: u32,
    pub task_failures: u32,
    pub no_progress_turns: u32,
    pub max_session_failures: u32,
    pub max_task_failures: u32,
    pub max_no_progress_turns: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureBudgetSnapshot {
    pub session_failures: u32,
    pub task_failures: u32,
    pub no_progress_turns: u32,
    pub max_session_failures: u32,
    pub max_task_failures: u32,
    pub max_no_progress_turns: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellRetryRecord {
    pub shell_session_id: String,
    pub shell_turn_id: String,
    pub retry_class: RetryClass,
    pub snapshot: FailureBudgetSnapshot,
    pub stop_condition: Option<StopCondition>,
}

impl Default for FailureBudget {
    fn default() -> Self {
        Self {
            session_failures: 0,
            task_failures: 0,
            no_progress_turns: 0,
            max_session_failures: 3,
            max_task_failures: 3,
            max_no_progress_turns: 5,
        }
    }
}

impl FailureBudget {
    pub fn snapshot(&self) -> FailureBudgetSnapshot {
        FailureBudgetSnapshot {
            session_failures: self.session_failures,
            task_failures: self.task_failures,
            no_progress_turns: self.no_progress_turns,
            max_session_failures: self.max_session_failures,
            max_task_failures: self.max_task_failures,
            max_no_progress_turns: self.max_no_progress_turns,
        }
    }

    pub fn record_failure(&mut self, retry_class: RetryClass) -> Option<StopCondition> {
        match retry_class {
            RetryClass::TransientModel
            | RetryClass::TransientCapability
            | RetryClass::TransientWorker
            | RetryClass::ApprovalTimeoutRetryable => {
                self.session_failures += 1;
                self.task_failures += 1;
                if self.session_failures >= self.max_session_failures
                    || self.task_failures >= self.max_task_failures
                {
                    return Some(StopCondition::FailureBudgetExhausted);
                }
            }
            RetryClass::StructuralNonRetryable => {
                return Some(StopCondition::StructuralValidationFailure);
            }
            RetryClass::PolicyNonRetryable => {
                return Some(StopCondition::GovernanceHardStop);
            }
        }

        None
    }

    pub fn note_progress(&mut self) {
        self.no_progress_turns = 0;
    }

    pub fn note_no_progress(&mut self) -> Option<StopCondition> {
        self.no_progress_turns += 1;
        if self.no_progress_turns >= self.max_no_progress_turns {
            return Some(StopCondition::NoProgressCeilingReached);
        }
        None
    }
}

pub fn apply_shell_retry(
    failure_budget: &mut FailureBudget,
    shell_session_id: impl Into<String>,
    shell_turn_id: impl Into<String>,
    retry_class: RetryClass,
) -> ShellRetryRecord {
    let stop_condition = failure_budget.record_failure(retry_class.clone());
    ShellRetryRecord {
        shell_session_id: shell_session_id.into(),
        shell_turn_id: shell_turn_id.into(),
        retry_class,
        snapshot: failure_budget.snapshot(),
        stop_condition,
    }
}

#[cfg(test)]
mod tests {
    use super::{FailureBudget, RetryClass, StopCondition, apply_shell_retry};

    #[test]
    fn structural_failure_is_immediate_stop() {
        let mut budget = FailureBudget::default();
        let stop = budget.record_failure(RetryClass::StructuralNonRetryable);
        assert_eq!(stop, Some(StopCondition::StructuralValidationFailure));
    }

    #[test]
    fn no_progress_reaches_ceiling() {
        let mut budget = FailureBudget {
            max_no_progress_turns: 2,
            ..FailureBudget::default()
        };

        assert_eq!(budget.note_no_progress(), None);
        assert_eq!(
            budget.note_no_progress(),
            Some(StopCondition::NoProgressCeilingReached)
        );
    }

    #[test]
    fn shell_retry_record_captures_snapshot_and_stop_condition() {
        let mut budget = FailureBudget {
            max_session_failures: 1,
            max_task_failures: 1,
            ..FailureBudget::default()
        };

        let record = apply_shell_retry(
            &mut budget,
            "shell-session-1",
            "shell-turn-1",
            RetryClass::TransientWorker,
        );

        assert_eq!(record.shell_session_id, "shell-session-1");
        assert_eq!(record.shell_turn_id, "shell-turn-1");
        assert_eq!(
            record.stop_condition,
            Some(StopCondition::FailureBudgetExhausted)
        );
        assert_eq!(record.snapshot.session_failures, 1);
    }
}
