package server

import (
	"log"
	"time"
)

// evidencePruneInterval is how often retention-expired evidence is removed.
// Bundles carry their own expiry (terminal recordings 30 days); this only
// decides how soon after it the encrypted objects actually leave the disk.
const evidencePruneInterval = time.Hour

// pruneExpiredEvidence removes evidence bundles past their retention date that
// are not on legal hold. Before this ran on a timer, expiry was enforced only
// when an operator called /api/v1/evidence/prune, so terminal transcripts and
// forensic collections stayed on disk indefinitely despite their 30-day stamp.
func (s *Server) pruneExpiredEvidence(now time.Time) {
	if s.evidenceStore == nil {
		return
	}
	count, err := s.evidenceStore.PruneExpiredBundles(now.UTC())
	if err != nil {
		log.Printf("[!] Evidence retention prune failed: %v", err)
		return
	}
	if count > 0 {
		log.Printf("[+] Evidence retention: pruned %d expired bundle(s)", count)
	}
}

// startEvidenceRetention prunes once immediately and then on every interval
// until stop is closed.
func (s *Server) startEvidenceRetention(interval time.Duration, stop <-chan struct{}) {
	s.pruneExpiredEvidence(time.Now())
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				s.pruneExpiredEvidence(now)
			}
		}
	}()
}
