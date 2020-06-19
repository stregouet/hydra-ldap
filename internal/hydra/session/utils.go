package session

// will keep only most recent session for each client
func Filter(sess []ConsentSession) []ConsentSession {
	byClient := make(map[string][]ConsentSession)
	for _, s := range sess {
		byClient[s.ConsentRequest.Client.Id] = append(byClient[s.ConsentRequest.Client.Id], s)
	}

	filtered := make([]ConsentSession, 0, len(byClient))
	for _, sessions := range byClient {
		mostRecent := sessions[0]
		for _, s := range sessions {
			if s.HandledAt.After(mostRecent.HandledAt) {
				mostRecent = s
			}
		}
		filtered = append(filtered, mostRecent)
	}
	return filtered
}
