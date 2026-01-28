// Copyright 2019-2022 Graham Clark. All rights reserved.  Use of this source
// code is governed by the MIT license that can be found in the LICENSE
// file.

// Package assets provides embedded static files for termshark.
package assets

import "embed"

// Themes contains the embedded theme files.
//
//go:embed themes/*.toml
var Themes embed.FS
