"""
PrivWatch 3.1 - Markov Sequence Transition Model
Evaluates state transitions across sequential Linux security events to detect multi-stage attack chains.
"""

from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional
import numpy as np

from core.models import SecurityEvent
from ml.features.feature_schema import FeatureVector


# State abstractions for Linux security events
MARKOV_STATES = [
    "UNPRIV_EXEC",       # Normal unprivileged execution
    "AUTH_FAILURE",      # Sudo or PAM authentication failure
    "SUDO_INVOKE",       # Authorized sudo command execution
    "SUID_ELEVATE",      # Active EUID 0 or SUID elevation
    "DAEMON_SERVICE",    # Service daemon process execution
    "CONFIG_TAMPER",     # Sensitive configuration file access/write
    "EVASION_EXEC",      # Execution from /tmp, /dev/shm, etc.
    "ROOT_EXEC",         # Standard root administrative activity
]


class MarkovPrivilegeSequenceModel:
    """
    First-order Markov Chain transition probability model.
    Models normal transitions between execution states and flags statistically improbable sequences.
    """

    def __init__(self, laplace_alpha: float = 0.05):
        self.laplace_alpha = laplace_alpha
        self.states = MARKOV_STATES
        self.state_to_idx = {s: i for i, s in enumerate(self.states)}
        self.n_states = len(self.states)

        # Transition matrix T[from_state, to_state]
        self.transition_matrix = np.full(
            (self.n_states, self.n_states),
            self.laplace_alpha,
            dtype=np.float64
        )
        self.initial_probs = np.full(self.n_states, 1.0 / self.n_states, dtype=np.float64)
        self.is_fitted: bool = False
        self.model_id = "markov_sequence_v3_1"

        # Initialize with baseline priors (normal administrative transitions have higher prior probability)
        self._init_baseline_priors()

    def _init_baseline_priors(self):
        """Seed transition matrix with realistic Linux operational baseline priors"""
        # Normal flow: UNPRIV_EXEC -> UNPRIV_EXEC
        self._add_prior("UNPRIV_EXEC", "UNPRIV_EXEC", 50.0)
        self._add_prior("UNPRIV_EXEC", "SUDO_INVOKE", 5.0)
        self._add_prior("SUDO_INVOKE", "ROOT_EXEC", 20.0)
        self._add_prior("ROOT_EXEC", "ROOT_EXEC", 30.0)
        self._add_prior("ROOT_EXEC", "UNPRIV_EXEC", 5.0)
        self._add_prior("DAEMON_SERVICE", "DAEMON_SERVICE", 40.0)
        self._add_prior("AUTH_FAILURE", "UNPRIV_EXEC", 20.0)
        self._add_prior("AUTH_FAILURE", "AUTH_FAILURE", 5.0)
        self._add_prior("SUID_ELEVATE", "UNPRIV_EXEC", 20.0)
        self._normalize_matrix()
        self.is_fitted = True

    def _add_prior(self, from_state: str, to_state: str, count: float):
        if from_state in self.state_to_idx and to_state in self.state_to_idx:
            i = self.state_to_idx[from_state]
            j = self.state_to_idx[to_state]
            self.transition_matrix[i, j] += count

    def _normalize_matrix(self):
        """Row-normalize transition matrix so rows sum to 1.0"""
        row_sums = self.transition_matrix.sum(axis=1, keepdims=True)
        self.transition_matrix = self.transition_matrix / np.where(row_sums > 0, row_sums, 1.0)

    @classmethod
    def map_event_to_state(cls, event: SecurityEvent, fv: Optional[FeatureVector] = None) -> str:
        """Map a SecurityEvent or FeatureVector to an abstract Markov state"""
        if fv:
            v = fv.values
            if v.get("exe_in_writable_dir", 0.0) == 1.0:
                return "EVASION_EXEC"
            if v.get("modifies_sensitive_file", 0.0) == 1.0:
                return "CONFIG_TAMPER"
            if v.get("uid_euid_mismatch", 0.0) == 1.0 and v.get("euid_is_root", 0.0) == 1.0:
                return "SUID_ELEVATE"
            if v.get("is_daemon_user", 0.0) == 1.0:
                return "DAEMON_SERVICE"
            if v.get("auth_fails_last_300s", 0.0) > 0.0 and event.event_type == "SUDO_AUTH_FAIL":
                return "AUTH_FAILURE"
            if event.event_type == "SUDO_COMMAND":
                return "SUDO_INVOKE"
            if v.get("uid_is_root", 0.0) == 1.0:
                return "ROOT_EXEC"
            return "UNPRIV_EXEC"

        # Direct event fallback
        etype = event.event_type
        if etype == "SUDO_AUTH_FAIL":
            return "AUTH_FAILURE"
        elif etype == "SUDO_COMMAND":
            return "SUDO_INVOKE"
        elif etype in ["SUID_EXECUTION", "ACTIVE_EUID_ELEVATION"]:
            return "SUID_ELEVATE"
        elif etype == "PROCESS_RUNNING_FROM_TMP":
            return "EVASION_EXEC"
        elif event.uid == 0 or event.euid == 0:
            return "ROOT_EXEC"
        return "UNPRIV_EXEC"

    def fit_sequences(self, sequences: List[List[str]]):
        """Update transition counts from observed state sequences"""
        counts = np.full((self.n_states, self.n_states), self.laplace_alpha, dtype=np.float64)
        for seq in sequences:
            if len(seq) < 2:
                continue
            for t in range(len(seq) - 1):
                s1 = seq[t]
                s2 = seq[t + 1]
                if s1 in self.state_to_idx and s2 in self.state_to_idx:
                    i = self.state_to_idx[s1]
                    j = self.state_to_idx[s2]
                    counts[i, j] += 1.0

        self.transition_matrix = counts
        self._normalize_matrix()
        self.is_fitted = True

    def score_sequence(self, sequence: List[str]) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Compute sequence anomaly score (0.0 to 1.0) and step-by-step transition probabilities.
        Returns: (sequence_anomaly_score, transition_details)
        """
        if len(sequence) < 2:
            return 0.10, []

        log_prob_sum = 0.0
        details: List[Dict[str, Any]] = []

        for t in range(len(sequence) - 1):
            s1 = sequence[t]
            s2 = sequence[t + 1]
            i = self.state_to_idx.get(s1, 0)
            j = self.state_to_idx.get(s2, 0)

            prob = float(self.transition_matrix[i, j])
            log_prob = float(np.log(max(prob, 1e-6)))
            log_prob_sum += log_prob

            # Flag rare transitions (p < 0.05)
            is_rare = (prob < 0.05)
            details.append({
                "from_state": s1,
                "to_state": s2,
                "transition_prob": round(prob, 4),
                "is_rare": is_rare
            })

        # Average log probability per transition step
        n_transitions = len(sequence) - 1
        avg_log_prob = log_prob_sum / n_transitions

        # Map log prob to anomaly score: normal avg_log_prob is around -1.0 to -2.0
        # Highly abnormal sequences have avg_log_prob < -4.0
        # Sigmoid: center around -3.0
        anomaly_score = float(1.0 / (1.0 + np.exp(1.5 * (avg_log_prob + 3.0))))

        return min(1.0, max(0.0, anomaly_score)), details
