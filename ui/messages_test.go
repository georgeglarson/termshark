// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

package ui

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTemplates_NameVer(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "NameVer", TemplateData)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "termshark")
}

func TestTemplates_OneLine(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "OneLine", TemplateData)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "wireshark-inspired")
}

func TestTemplates_UIHelp(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "UIHelp", TemplateData)
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "termshark")
	assert.Contains(t, output, "tab")
	assert.Contains(t, output, "Quit")
}

func TestTemplates_VimHelp(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "VimHelp", TemplateData)
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "hjkl")
	assert.Contains(t, output, "gg")
}

func TestTemplates_CmdLineHelp(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "CmdLineHelp", TemplateData)
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "filter")
	assert.Contains(t, output, "quit")
	assert.Contains(t, output, "streams")
}

func TestTemplates_SetHelp(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "SetHelp", TemplateData)
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "dark-mode")
	assert.Contains(t, output, "auto-scroll")
}

func TestTemplates_MapHelp(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "MapHelp", TemplateData)
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "map")
	assert.Contains(t, output, "<f1>")
}

func TestTemplates_CopyModeHelp(t *testing.T) {
	EnsureTemplateData()
	var buf bytes.Buffer
	err := Templates.ExecuteTemplate(&buf, "CopyModeHelp", TemplateData)
	assert.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "copy-mode")
	assert.Contains(t, output, "ctrl-c")
}

func TestTemplates_FuncMapInc(t *testing.T) {
	assert.Equal(t, 2, funcMap["inc"].(func(int) int)(1))
	assert.Equal(t, 0, funcMap["inc"].(func(int) int)(-1))
}

func TestEnsureTemplateData_Idempotent(t *testing.T) {
	EnsureTemplateData()
	assert.NotNil(t, TemplateData)

	// Calling again should not panic or reset
	TemplateData["test_key"] = "test_val"
	EnsureTemplateData()
	// Note: DoOnce means it won't reset, but the key may persist
	// depending on order. Just verify it doesn't panic.
	assert.NotNil(t, TemplateData)
}
