//go:build !linux && !darwin

package scanner

// measureTTL has no unprivileged implementation on this platform, so the hop
// limit is reported as unmeasured. The matcher scores 0 as no evidence, which
// is the correct answer rather than a default that quietly votes for Linux.
func measureTTL(string) int { return 0 }

// TTLMeasurable says so plainly on a platform with no unprivileged path to it.
func TTLMeasurable() (bool, string) {
	return false, "hop limits cannot be measured without privilege on this platform, and contribute nothing to an identification"
}
