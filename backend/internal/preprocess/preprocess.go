package preprocess

import (
	"regexp"
	"strings"
)

var (
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reLineComment  = regexp.MustCompile(`(?m)//.*$`)
	reSPDX         = regexp.MustCompile(`(?m)^\s*//\s*SPDX-License-Identifier:.*$`)
	rePragma       = regexp.MustCompile(`(?m)^\s*pragma\s+solidity\s+[^;]+;\s*$`)
)

func Run(source string) string {
	s := strings.ReplaceAll(source, "\r\n", "\n")

	// 先删 SPDX（通常是行注释），避免被通用注释规则干扰
	s = reSPDX.ReplaceAllString(s, "")

	// 去注释
	s = reBlockComment.ReplaceAllString(s, "")
	s = reLineComment.ReplaceAllString(s, "")

	// 去 pragma solidity（对模型输入常是冗余；后续可按需保留）
	s = rePragma.ReplaceAllString(s, "")

	// 去尾随空白 + 压缩空行
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	blankStreak := 0
	for _, line := range lines {
		trimRight := strings.TrimRight(line, " \t")
		if strings.TrimSpace(trimRight) == "" {
			blankStreak++
			if blankStreak <= 1 {
				out = append(out, "")
			}
			continue
		}
		blankStreak = 0
		out = append(out, trimRight)
	}

	// 去头尾空行
	for len(out) > 0 && strings.TrimSpace(out[0]) == "" {
		out = out[1:]
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}

	return strings.Join(out, "\n")
}

func CountLines(source string) int {
	if source == "" {
		return 0
	}
	s := strings.ReplaceAll(source, "\r\n", "\n")
	return len(strings.Split(s, "\n"))
}
