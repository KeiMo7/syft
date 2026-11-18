package exclusions

import (
	"fmt"
	"strings"
)

type Action string

const (
	ExcludeAction Action = "exclude"
	IncludeAction Action = "include"
)

// RuleConfig describes one exclusion rule. A rule matches a package when every populated
// dimension matches. Path and layer dimensions are evaluated against the package's discovery
// locations, while the ecosystem dimension is evaluated against the package itself.
type RuleConfig struct {
	Action    Action `json:"action,omitempty" yaml:"action,omitempty" mapstructure:"action"`
	Path      string `json:"path,omitempty" yaml:"path,omitempty" mapstructure:"path"`
	Ecosystem string `json:"ecosystem,omitempty" yaml:"ecosystem,omitempty" mapstructure:"ecosystem"`
	Layer     string `json:"layer,omitempty" yaml:"layer,omitempty" mapstructure:"layer"`
}

func (r RuleConfig) Empty() bool {
	return strings.TrimSpace(r.Path) == "" &&
		strings.TrimSpace(r.Ecosystem) == "" &&
		strings.TrimSpace(r.Layer) == ""
}

func (r RuleConfig) action() Action {
	switch Action(strings.ToLower(strings.TrimSpace(string(r.Action)))) {
	case "", ExcludeAction:
		return ExcludeAction
	case IncludeAction:
		return IncludeAction
	default:
		return Action(strings.ToLower(strings.TrimSpace(string(r.Action))))
	}
}

// Config controls package exclusion. An empty rule list preserves the default scan behavior.
type Config struct {
	Rules     []RuleConfig `json:"rules,omitempty" yaml:"rules,omitempty" mapstructure:"rules"`
	AuditFile string       `json:"audit-file,omitempty" yaml:"audit-file,omitempty" mapstructure:"audit-file"`
}

func (c Config) Enabled() bool {
	return len(c.Rules) > 0
}

func (c Config) Validate() error {
	_, err := NewMatcher(c)
	return err
}

// ParseRuleExpression parses the command-line form of a rule, for example:
//
//	path=**/vendor/**,ecosystem=go
//	action=include,path=app/vendor/runtime/**
func ParseRuleExpression(value string) (RuleConfig, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return RuleConfig{}, fmt.Errorf("rule expression is empty")
	}

	var rule RuleConfig
	for _, field := range strings.Split(value, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		key, val, ok := strings.Cut(field, "=")
		if !ok {
			return RuleConfig{}, fmt.Errorf("expected key=value, got %q", field)
		}

		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if val == "" {
			return RuleConfig{}, fmt.Errorf("%s must not be empty", key)
		}

		switch key {
		case "action":
			rule.Action = Action(strings.ToLower(val))
		case "path", "glob", "path-glob":
			rule.Path = val
		case "ecosystem", "manager", "package-manager":
			rule.Ecosystem = val
		case "layer", "layer-id", "layer-digest":
			rule.Layer = val
		default:
			return RuleConfig{}, fmt.Errorf("unknown field %q", key)
		}
	}

	if rule.Empty() {
		return RuleConfig{}, fmt.Errorf("rule must contain at least one of path, ecosystem, or layer")
	}
	if action := rule.action(); action != ExcludeAction && action != IncludeAction {
		return RuleConfig{}, fmt.Errorf("invalid action %q (expected exclude or include)", rule.Action)
	}

	return rule, nil
}
