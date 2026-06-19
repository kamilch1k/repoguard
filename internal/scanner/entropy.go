package scanner

import "math"

func ShannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}

	counts := map[rune]int{}
	for _, r := range value {
		counts[r]++
	}

	length := float64(len([]rune(value)))
	var entropy float64
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
