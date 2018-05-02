// +build windows

package cmd

import "strings"

func cleanSuffix(s string) string {
	return strings.TrimSuffix(strings.TrimSuffix(s, "\n"), "\r")
}
