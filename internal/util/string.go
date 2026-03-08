package util

// TruncateString truncates s to maxLen characters and appends "..." if truncated.
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
