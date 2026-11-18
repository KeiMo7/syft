package cataloging

import (
	"time"

	"github.com/anchore/syft/syft/event/monitor"
)

const DefaultProgressInterval = 30 * time.Second

// ProgressConfig controls stage-level cataloging progress reporting. It is disabled by default.
type ProgressConfig struct {
	Enabled  bool                                   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Interval time.Duration                          `yaml:"interval" json:"interval" mapstructure:"interval"`
	Sink     func(monitor.CatalogingProgress) error `yaml:"-" json:"-" mapstructure:"-"`
}

func DefaultProgressConfig() ProgressConfig {
	return ProgressConfig{
		Enabled:  false,
		Interval: DefaultProgressInterval,
	}
}

func (c ProgressConfig) WithEnabled(enabled bool) ProgressConfig {
	c.Enabled = enabled
	return c
}

func (c ProgressConfig) WithInterval(interval time.Duration) ProgressConfig {
	c.Interval = interval
	return c
}

func (c ProgressConfig) WithSink(sink func(monitor.CatalogingProgress) error) ProgressConfig {
	c.Sink = sink
	return c
}
