package preprocess

import (
	"regexp"
	"strings"

	solcparser "github.com/umbracle/solidity-parser-go"
)

var (
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reLineComment  = regexp.MustCompile(`(?m)//.*$`)
	reSPDX         = regexp.MustCompile(`(?m)^\s*//\s*SPDX-License-Identifier:.*$`)
	rePragma       = regexp.MustCompile(`(?m)^\s*pragma\s+solidity\s+[^;]+;\s*$`)
	reImport       = regexp.MustCompile(`(?m)^\s*import\s+[^;]+;\s*$`)
	reUsingFor     = regexp.MustCompile(`(?m)^\s*using\s+[^;]+;\s*$`)
)

func Run(source string) string {
	s := normalizeNewlines(source)
	s = stripBasicRedundancy(s)
	return compressWhitespace(s)
}

// RunAST 在 Run 的基础上增加“语法解析校验 + 结构性冗余去除”：
// - 先做注释/SPDX/pragma 的剥离（避免解析被干扰）
// - 解析 Solidity 语法（若有语法错误则回退为基础 Run 结果）
// - 在解析通过的前提下，再移除 import / using for 等结构性冗余（行级）
//
// 说明：当前解析库不提供节点的源代码位置与格式化器，因此本阶段采用“解析校验 + 行级规则剥离”。
func RunAST(source string) string {
	s := normalizeNewlines(source)
	s = stripBasicRedundancy(s)

	p := solcparser.Parse(s)
	if p == nil || len(p.Errors) > 0 {
		return compressWhitespace(s)
	}

	s = reImport.ReplaceAllString(s, "")
	s = reUsingFor.ReplaceAllString(s, "")
	return compressWhitespace(s)
}

func normalizeNewlines(source string) string {
	return strings.ReplaceAll(source, "\r\n", "\n")
}

func stripBasicRedundancy(s string) string {
	// 先删 SPDX（通常是行注释），避免被通用注释规则干扰
	s = reSPDX.ReplaceAllString(s, "")

	// 去注释
	s = reBlockComment.ReplaceAllString(s, "")
	s = reLineComment.ReplaceAllString(s, "")

	// 去 pragma solidity（对模型输入常是冗余；后续可按需保留）
	s = rePragma.ReplaceAllString(s, "")
	return s
}

func compressWhitespace(s string) string {
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
	s := normalizeNewlines(source)
	return len(strings.Split(s, "\n"))
}
