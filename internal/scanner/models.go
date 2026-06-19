package scanner

type Severity string

const (
	SeverityInfo  Severity = "info"
	SeverityWarn  Severity = "warn"
	SeverityError Severity = "error"
)

type Config struct {
	MaxFileBytes     int64   `json:"maxFileBytes,omitempty"`
	EntropyThreshold float64 `json:"entropyThreshold,omitempty"`
	EnableEntropy    bool    `json:"enableEntropy"`
}

type FileInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type Finding struct {
	RuleID   string   `json:"ruleId"`
	Severity Severity `json:"severity"`
	Path     string   `json:"path"`
	Line     int      `json:"line"`
	Column   int      `json:"column"`
	Detector string   `json:"detector"`
	Snippet  string   `json:"snippet"`
	Reason   string   `json:"reason"`
	Entropy  float64  `json:"entropy,omitempty"`
}

type Summary struct {
	FilesScanned int `json:"filesScanned"`
	Errors       int `json:"errors"`
	Warnings     int `json:"warnings"`
	Infos        int `json:"infos"`
}

type Report struct {
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
}

func DefaultConfig() Config {
	return Config{
		MaxFileBytes:     1 << 20,
		EntropyThreshold: 4.2,
		EnableEntropy:    true,
	}
}

func (r *Report) add(f Finding) {
	r.Findings = append(r.Findings, f)
	switch f.Severity {
	case SeverityError:
		r.Summary.Errors++
	case SeverityWarn:
		r.Summary.Warnings++
	default:
		r.Summary.Infos++
	}
}
