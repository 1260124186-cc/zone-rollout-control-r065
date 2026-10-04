package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

func ActivatePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanDraft {
		return InvalidState("plan can be activated only from draft", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	if plan.LatestRevisionID == "" {
		return InvalidState("plan needs a zone revision before activation", map[string]any{
			"plan_id": plan.ID,
		})
	}
	plan.State = PlanActive
	plan.ActivatedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func CompletePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanActive {
		return InvalidState("plan can be completed only from active", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	plan.State = PlanCompleted
	plan.CompletedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func LeaseFingerprint(planID string, input LeaseInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%d|%d",
		planID,
		input.RequestKey,
		input.Region,
		input.LeaseSeconds,
		input.MaxNodes,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func ProbeFingerprint(leaseID string, input ProbeInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%t|%d|%d|%s",
		leaseID,
		input.RequestKey,
		input.Success,
		input.ObservedSerial,
		input.LatencyMS,
		input.ObservedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func BuildAssessment(
	id string,
	plan RolloutPlan,
	policy PlanPolicy,
	revision ZoneRevision,
	probes []Probe,
	now time.Time,
) RolloutAssessment {
	reasons := make(map[string]struct{})
	if len(probes) == 0 {
		reasons["no_probes"] = struct{}{}
	}
	probeCount := len(probes)
	successCount := 0
	maximumLatency := 0
	nodes := make(map[string]struct{})
	for _, probe := range probes {
		nodes[probe.NodeID] = struct{}{}
		if probe.LatencyMS > maximumLatency {
			maximumLatency = probe.LatencyMS
		}
		if probe.Success {
			successCount++
			if probe.ObservedSerial != revision.Serial {
				reasons["serial_mismatch"] = struct{}{}
			}
		}
	}
	if len(nodes) < plan.ExpectedNodes {
		reasons["node_not_observed"] = struct{}{}
	}
	successRatio := 0.0
	if probeCount > 0 {
		successRatio = round(float64(successCount)/float64(probeCount), 6)
	}
	if successRatio < policy.MinimumSuccessRatio {
		reasons["success_ratio_below_minimum"] = struct{}{}
	}
	if maximumLatency > policy.MaximumLatencyMS {
		reasons["latency_limit_exceeded"] = struct{}{}
	}
	reasonList := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonList = append(reasonList, reason)
	}
	sort.Strings(reasonList)
	verdict := VerdictConsistent
	if len(reasonList) > 0 {
		verdict = VerdictReviewRequired
	}
	return RolloutAssessment{
		ID:               id,
		PlanID:           plan.ID,
		RevisionID:       revision.ID,
		Verdict:          verdict,
		Reasons:          reasonList,
		ProbeCount:       probeCount,
		SuccessCount:     successCount,
		SuccessRatio:     successRatio,
		MaximumLatencyMS: maximumLatency,
		CreatedAt:        now.UTC(),
	}
}

// PolicyFromPlan reads the assessment thresholds a plan was created with.
func PolicyFromPlan(plan RolloutPlan) PlanPolicy {
	return PlanPolicy{
		MinimumSuccessRatio: plan.MinimumSuccessRatio,
		MaximumLatencyMS:    plan.MaximumLatencyMS,
	}
}

// policyKey names the shared bucket a plan's thresholds are registered under.
func policyKey(plan RolloutPlan) string {
	return canonicalName(plan.Zone)
}

// RegisterPlanPolicy records a plan's thresholds so later reads and assessments
// can resolve them without keeping them on the plan aggregate itself.
func RegisterPlanPolicy(state *State, plan RolloutPlan) PlanPolicy {
	policy := PolicyFromPlan(plan)
	state.PlanPolicies[policyKey(plan)] = policy
	return policy
}

// PlanPolicyFor resolves the thresholds used to assess a plan.
func PlanPolicyFor(state *State, plan RolloutPlan) PlanPolicy {
	if state == nil {
		return PlanPolicy{}
	}
	if policy, ok := state.PlanPolicies[policyKey(plan)]; ok {
		return policy
	}
	return PlanPolicy{}
}

// ApplyPlanPolicy projects the registered thresholds back onto a plan for
// responses and reads.
func ApplyPlanPolicy(state *State, plan RolloutPlan) RolloutPlan {
	policy := PlanPolicyFor(state, plan)
	plan.MinimumSuccessRatio = policy.MinimumSuccessRatio
	plan.MaximumLatencyMS = policy.MaximumLatencyMS
	return plan
}

// RebuildPlanPolicies reconstructs the threshold registry from the persisted
// plans whenever a snapshot is loaded.
func RebuildPlanPolicies(state *State) {
	if state == nil {
		return
	}
	policies := make(map[string]PlanPolicy, len(state.Plans))
	for _, plan := range state.Plans {
		policies[policyKey(plan)] = PolicyFromPlan(plan)
	}
	state.PlanPolicies = policies
}

func round(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

func timePointer(value time.Time) *time.Time {
	return &value
}
