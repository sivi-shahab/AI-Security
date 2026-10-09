package mcpgw

import (
	"sync"
	"time"
)

// Agent behaviour analytics (ticket 39, OWASP ASI08 cascading failures, ASI10 rogue agents): each agent's tool calls
// build a baseline (tools used, tool-to-tool transitions, calls per minute); a call that leaves it is reported to
// the PDP and in the decision event as behavior_anomalies, where the risk floor "agent-behavior-anomaly" makes it an
// incident. The baseline keeps learning, so a new tool is flagged on its first calls, not forever.
//
// ponytail: in-memory per replica and rebuilt (warm-up) after a restart; persist profiles or move the analysis to
// an event-stream consumer if agents must be watched from the first call after a deploy.

// Anomaly kinds.
const (
	AnomalyNewTool      = "new_tool"      // a tool this agent has not called before
	AnomalyRareSequence = "rare_sequence" // a transition from the previous tool this agent has not made before
	AnomalyVolumeSpike  = "volume_spike"  // far more calls this minute than the agent's usual rate
)

// BehaviorConfig: an agent is judged only after Warmup calls; a transition is judged once the previous tool has led
// somewhere MinFrom times; a minute is a spike above max(SpikeFactor × usual rate, SpikeFloor) calls.
type BehaviorConfig struct {
	Warmup      int
	MinFrom     int
	SpikeFactor float64
	SpikeFloor  int
}

var DefaultBehavior = BehaviorConfig{Warmup: 50, MinFrom: 20, SpikeFactor: 5, SpikeFloor: 20}

type profile struct {
	calls  int
	tools  map[string]int
	from   map[string]int            // transitions out of a tool
	next   map[string]map[string]int // prev → tool → count
	prev   map[string]string         // session → its last tool
	minute time.Time
	inMin  int
	rate   float64 // calls per active minute, exponentially weighted
}

// Behavior holds the agents' profiles.
type Behavior struct {
	Config BehaviorConfig
	mu     sync.Mutex
	agents map[string]*profile
}

// maxSessions bounds the per-agent session map; past it the map starts over (a few transitions go unjudged).
const maxSessions = 10000

// Observe judges one tool call against the agent's baseline, then learns it. session orders calls into sequences
// (the agent's trace, so parallel tasks of one agent do not interleave). The result is nil when nothing is unusual.
func (b *Behavior) Observe(agent, session, tool string, now time.Time) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.agents == nil {
		b.agents = map[string]*profile{}
	}
	cfg := b.Config
	if cfg == (BehaviorConfig{}) {
		cfg = DefaultBehavior
	}
	p := b.agents[agent]
	if p == nil {
		p = &profile{tools: map[string]int{}, from: map[string]int{}, next: map[string]map[string]int{}, prev: map[string]string{}}
		b.agents[agent] = p
	}
	m := now.Truncate(time.Minute)
	if !m.Equal(p.minute) {
		switch {
		case p.inMin > 0 && p.rate == 0:
			p.rate = float64(p.inMin)
		case p.inMin > 0:
			p.rate = 0.8*p.rate + 0.2*float64(p.inMin)
		}
		p.minute, p.inMin = m, 0
	}
	p.inMin++

	prev := p.prev[session]
	var out []string
	if p.calls >= cfg.Warmup {
		if p.tools[tool] == 0 {
			out = append(out, AnomalyNewTool)
		}
		if prev != "" && p.from[prev] >= cfg.MinFrom && p.next[prev][tool] == 0 {
			out = append(out, AnomalyRareSequence)
		}
		if p.rate > 0 && float64(p.inMin) > max(cfg.SpikeFactor*p.rate, float64(cfg.SpikeFloor)) {
			out = append(out, AnomalyVolumeSpike)
		}
	}

	p.calls++
	p.tools[tool]++
	if prev != "" {
		p.from[prev]++
		if p.next[prev] == nil {
			p.next[prev] = map[string]int{}
		}
		p.next[prev][tool]++
	}
	if len(p.prev) >= maxSessions {
		clear(p.prev)
	}
	p.prev[session] = tool
	return out
}
