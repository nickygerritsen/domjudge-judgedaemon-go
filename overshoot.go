package main

import (
	"fmt"
	"math"
	"strings"
)

func overshootTime(timelimit float64, overshootConfig string) float64 {
	separators := []string{"+", "|", "&"}
	for _, separator := range separators {
		tokens := strings.Split(overshootConfig, separator)
		if len(tokens) > 2 {
			Error("invalid timelimit overshoot string '%v'", overshootConfig)
		} else if len(tokens) == 1 {
			continue
		}

		// We have split the string correctly, determine the two parts
		val1 := overshootParse(timelimit, tokens[0])
		val2 := overshootParse(timelimit, tokens[1])

		switch separator {
		case "+":
			return val1 + val2
		case "|":
			return math.Max(val1, val2)
		case "&":
			return math.Min(val1, val2)
		}
	}

	// If we are here, we only have one part in the overshoot config
	return overshootParse(timelimit, overshootConfig)
}

func overshootParse(timelimit float64, token string) float64 {
	var val int
	var overshootType int32
	if n, _ := fmt.Sscanf(token, "%d%c", &val, &overshootType); n != 2 {
		Error("invalid timelimit overshoot token '%v'", token)
	}

	// Note that Golangs fmt.Sscanf can not determine how much it scanned. For now, build up the original string again to check
	if token != fmt.Sprintf("%d%c", val, overshootType) {
		Error("invalid timelimit overshoot token '%v'", token)
	}

	if val < 0 {
		Error("timelimit overshoot cannot be negative: '%v'", token)
	}

	switch overshootType {
	case 's':
		return float64(val)
	case '%':
		return timelimit * 0.01 * float64(val)
	default:
		Error("invalid timelimit overshoot token '%v'", token)
		// never called but compiler complains otherwise
		return 0
	}
}
