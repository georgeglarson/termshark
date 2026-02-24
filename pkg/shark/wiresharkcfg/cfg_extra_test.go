package wiresharkcfg

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================
// Config parsing via ParseReader
//======================================================================

func TestParseReader_EmptyInput(t *testing.T) {
	// Empty input should fail to parse (parser needs at least one entry)
	_, err := ParseReader("", strings.NewReader(""))
	assert.Error(t, err, "empty input should not parse successfully")
}

func TestParseReader_OnlyNewlines(t *testing.T) {
	_, err := ParseReader("", strings.NewReader("\n\n\n"))
	assert.Error(t, err, "only newlines should not parse successfully")
}

func TestParseReader_OnlyComments(t *testing.T) {
	input := "# This is a comment\n# Another comment\n"
	_, err := ParseReader("", input_reader(input))
	// Comments alone are not entries, so parsing should fail
	assert.Error(t, err)
}

func TestParseReader_SingleStringKeyValue(t *testing.T) {
	input := "\ngui.toolbar: TRUE\n\n"
	parsed, err := ParseReader("", input_reader(input))
	assert.NoError(t, err)
	cfg := parsed.(*Config)
	assert.Equal(t, " TRUE", cfg.Strings["gui.toolbar"])
}

func TestParseReader_MultipleStringKeyValues(t *testing.T) {
	input := "\nfoo.bar: value1\n\nbaz.qux: value2\n\n"
	parsed, err := ParseReader("", input_reader(input))
	assert.NoError(t, err)
	cfg := parsed.(*Config)
	assert.Equal(t, " value1", cfg.Strings["foo.bar"])
	assert.Equal(t, " value2", cfg.Strings["baz.qux"])
}

func TestParseReader_StringValueWithSpaces(t *testing.T) {
	input := "\nsome.key: hello world foo\n\n"
	parsed, err := ParseReader("", input_reader(input))
	assert.NoError(t, err)
	cfg := parsed.(*Config)
	assert.Equal(t, " hello world foo", cfg.Strings["some.key"])
}

func TestParseReader_CommentsBeforeEntry(t *testing.T) {
	input := "# This is a comment\n\nsome.key: val\n\n"
	parsed, err := ParseReader("", input_reader(input))
	assert.NoError(t, err)
	cfg := parsed.(*Config)
	assert.Equal(t, " val", cfg.Strings["some.key"])
}

func TestParseReader_ColumnFormatList(t *testing.T) {
	input := "\ngui.column.format: \"No.\", \"%m\", \"Time\", \"%t\"\n\n"
	parsed, err := ParseReader("", input_reader(input))
	assert.NoError(t, err)
	cfg := parsed.(*Config)
	list := cfg.GetList("gui.column.format")
	assert.NotNil(t, list)
	assert.True(t, len(list) > 0, "should have parsed list items")
}

func TestParseReader_ColumnHiddenList(t *testing.T) {
	input := "\ngui.column.hidden: a, b, c\n\n"
	parsed, err := ParseReader("", input_reader(input))
	assert.NoError(t, err)
	cfg := parsed.(*Config)
	list := cfg.GetList("gui.column.hidden")
	assert.NotNil(t, list)
}

func TestParseReader_MixedEntries(t *testing.T) {
	input := "\ngui.column.format: \"No.\", \"%m\"\n\nsome.string: value\n\n"
	parsed, err := ParseReader("", input_reader(input))
	assert.NoError(t, err)
	cfg := parsed.(*Config)
	assert.NotNil(t, cfg.Lists["gui.column.format"])
	assert.Equal(t, " value", cfg.Strings["some.string"])
}

//======================================================================
// Config.GetList edge cases
//======================================================================

func TestConfig_GetList_EmptyMaps(t *testing.T) {
	c := &Config{
		Strings: map[string]string{},
		Lists:   map[string][]string{},
	}
	assert.Nil(t, c.GetList("any.key"))
}

func TestConfig_GetList_EmptyListValue(t *testing.T) {
	c := &Config{
		Strings: map[string]string{},
		Lists: map[string][]string{
			"empty.list": {},
		},
	}
	result := c.GetList("empty.list")
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

//======================================================================
// Config.ColumnFormat edge cases
//======================================================================

func TestConfig_ColumnFormat_Missing(t *testing.T) {
	c := &Config{
		Strings: map[string]string{},
		Lists:   map[string][]string{},
	}
	assert.Nil(t, c.ColumnFormat())
}

func TestConfig_ColumnFormat_NilConfig(t *testing.T) {
	var c *Config
	assert.Nil(t, c.GetList("gui.column.format"))
}

//======================================================================
// Config.merge edge cases
//======================================================================

func TestConfig_merge_EmptyOther(t *testing.T) {
	c1 := &Config{
		Strings: map[string]string{"k": "v"},
		Lists:   map[string][]string{"l": {"a"}},
	}
	c2 := &Config{
		Strings: map[string]string{},
		Lists:   map[string][]string{},
	}
	c1.merge(c2)
	assert.Equal(t, "v", c1.Strings["k"])
	assert.Equal(t, []string{"a"}, c1.Lists["l"])
}

func TestConfig_merge_EmptyBase(t *testing.T) {
	c1 := &Config{
		Strings: map[string]string{},
		Lists:   map[string][]string{},
	}
	c2 := &Config{
		Strings: map[string]string{"k": "v"},
		Lists:   map[string][]string{"l": {"a"}},
	}
	c1.merge(c2)
	assert.Equal(t, "v", c1.Strings["k"])
	assert.Equal(t, []string{"a"}, c1.Lists["l"])
}

//======================================================================
// Config.String edge cases
//======================================================================

func TestConfig_String_EmptyConfig(t *testing.T) {
	c := &Config{
		Strings: map[string]string{},
		Lists:   map[string][]string{},
	}
	assert.Equal(t, "", c.String())
}

func TestConfig_String_OnlyStrings(t *testing.T) {
	c := &Config{
		Strings: map[string]string{"a": "1"},
		Lists:   map[string][]string{},
	}
	assert.Equal(t, "a: 1", c.String())
}

func TestConfig_String_OnlyLists(t *testing.T) {
	c := &Config{
		Strings: map[string]string{},
		Lists:   map[string][]string{"x": {"p", "q"}},
	}
	assert.Equal(t, "x: p, q", c.String())
}

//======================================================================
// Config.PopulateFrom edge cases
//======================================================================

func TestConfig_PopulateFrom_EmptyFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "wscfg_empty*.prefs")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	c := &Config{}
	err = c.PopulateFrom(tmpfile.Name())
	// Empty file should fail to parse
	assert.Error(t, err)
}

func TestConfig_PopulateFrom_ValidSimpleConfig(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "wscfg_valid*.prefs")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := "\nfoo.bar: baz\n\n"
	_, err = tmpfile.WriteString(content)
	assert.NoError(t, err)
	tmpfile.Close()

	c := &Config{}
	err = c.PopulateFrom(tmpfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, " baz", c.Strings["foo.bar"])
}

func TestConfig_PopulateFrom_ConfigWithComments(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "wscfg_comments*.prefs")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := "# comment line\n\nsome.pref: TRUE\n\n"
	_, err = tmpfile.WriteString(content)
	assert.NoError(t, err)
	tmpfile.Close()

	c := &Config{}
	err = c.PopulateFrom(tmpfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, " TRUE", c.Strings["some.pref"])
}

func TestConfig_PopulateFrom_DirectoryPath(t *testing.T) {
	c := &Config{}
	err := c.PopulateFrom("/tmp")
	assert.Error(t, err)
}

//======================================================================
// Sentinel errors
//======================================================================

func TestNotFoundError_String(t *testing.T) {
	assert.Contains(t, NotFoundError.Error(), "wireshark preferences")
}

func TestNotParsedError_String(t *testing.T) {
	assert.Contains(t, NotParsedError.Error(), "parse")
}

//======================================================================
// Helpers
//======================================================================

func input_reader(s string) *strings.Reader {
	return strings.NewReader(s)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
