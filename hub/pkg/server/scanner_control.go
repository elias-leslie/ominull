package server

// StartDHCPSnooping enables the scanner's passive DHCP listener. Hub startup
// does not call this unless the operator explicitly opts in.
func (s *Server) StartDHCPSnooping() error {
	return s.scanner.StartDHCPSnooping()
}

// DHCPSnooping reports whether the passive DHCP listener is active.
func (s *Server) DHCPSnooping() bool {
	return s.scanner.DHCPSnooping()
}
