package shark

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

//======================================================================
// PsmlField.FromString edge cases
//======================================================================

func TestPsmlField_FromString_EmptyString(t *testing.T) {
	var p PsmlField
	err := p.FromString("")
	// Empty string has no colons, so len(fields)==1, fields[0]="" which is not "%Cus"
	assert.NoError(t, err)
	assert.Equal(t, PsmlField{Token: ""}, p)
}

func TestPsmlField_FromString_ThreeColonFields(t *testing.T) {
	var p PsmlField
	// 3 fields is invalid (need 1 or 4)
	err := p.FromString("a:b:c")
	assert.Equal(t, InvalidCustomColumnError, err)
}

func TestPsmlField_FromString_FiveColonFields(t *testing.T) {
	var p PsmlField
	// 5 fields is invalid
	err := p.FromString("a:b:c:d:e")
	assert.Equal(t, InvalidCustomColumnError, err)
}

func TestPsmlField_FromString_ValidFourFieldsNegativeOccurrence(t *testing.T) {
	var p PsmlField
	err := p.FromString("%Cus:ip.src:-1:R")
	assert.NoError(t, err)
	assert.Equal(t, "%Cus", p.Token)
	assert.Equal(t, "ip.src", p.Filter)
	assert.Equal(t, -1, p.Occurrence)
}

func TestPsmlField_FromString_ValidFourFieldsLargeOccurrence(t *testing.T) {
	var p PsmlField
	err := p.FromString("%Cus:tcp.port:999:R")
	assert.NoError(t, err)
	assert.Equal(t, 999, p.Occurrence)
}

func TestPsmlField_FromString_EmptyOccurrenceField(t *testing.T) {
	var p PsmlField
	// occurrence field is empty string -> ParseInt fails
	err := p.FromString("%Cus:ip.src::R")
	assert.Equal(t, InvalidCustomColumnError, err)
}

func TestPsmlField_FromString_SpecialCharsInFilter(t *testing.T) {
	var p PsmlField
	err := p.FromString("%m")
	assert.NoError(t, err)
	assert.Equal(t, PsmlField{Token: "%m"}, p)

	// Now with a single token that contains special chars (not %Cus)
	var p2 PsmlField
	err = p2.FromString("%@#!")
	assert.NoError(t, err)
	assert.Equal(t, PsmlField{Token: "%@#!"}, p2)
}

func TestPsmlField_FromString_WhitespaceToken(t *testing.T) {
	var p PsmlField
	err := p.FromString("  ")
	assert.NoError(t, err)
	assert.Equal(t, PsmlField{Token: "  "}, p)
}

func TestPsmlField_FromString_OnlyColons(t *testing.T) {
	var p PsmlField
	// ":::" splits into 4 empty fields, ParseInt("",10,32) fails
	err := p.FromString(":::")
	assert.Equal(t, InvalidCustomColumnError, err)
}

//======================================================================
// PsmlField.String and FullString edge cases
//======================================================================

func TestPsmlField_String_EmptyFilter(t *testing.T) {
	p := PsmlField{Token: "%t", Filter: "", Occurrence: 0}
	assert.Equal(t, "%t", p.String())
}

func TestPsmlField_String_NonEmptyFilter(t *testing.T) {
	p := PsmlField{Token: "%Cus", Filter: "frame.len", Occurrence: 5}
	assert.Equal(t, "%Cus:frame.len:5:R", p.String())
}

func TestPsmlField_FullString_ZeroOccurrence(t *testing.T) {
	p := PsmlField{Token: "%m", Filter: "", Occurrence: 0}
	assert.Equal(t, "%m::0:R", p.FullString())
}

func TestPsmlField_FullString_EmptyTokenAndFilter(t *testing.T) {
	p := PsmlField{Token: "", Filter: "", Occurrence: 0}
	assert.Equal(t, "::0:R", p.FullString())
}

//======================================================================
// PsmlColumnInfo.WithLongName
//======================================================================

func TestPsmlColumnInfo_WithLongName_PreservesOtherFields(t *testing.T) {
	info := PsmlColumnInfo{
		Field: "%L",
		Short: "Length",
		Long:  "Packet length (bytes)",
	}
	updated := info.WithLongName("Custom Long Name")
	assert.Equal(t, "Custom Long Name", updated.Long)
	assert.Equal(t, "%L", updated.Field)
	assert.Equal(t, "Length", updated.Short)
	// Original unchanged
	assert.Equal(t, "Packet length (bytes)", info.Long)
}

func TestPsmlColumnInfo_WithLongName_EmptyString(t *testing.T) {
	info := PsmlColumnInfo{Long: "something"}
	updated := info.WithLongName("")
	assert.Equal(t, "", updated.Long)
}

//======================================================================
// ColumnsFromTshark.InitNoCache - parsing tshark output
//======================================================================

func TestColumnsFromTshark_InitNoCache_ParsesOutput(t *testing.T) {
	// This is an integration test that requires tshark; TestCF1 already covers it.
	// We test that the result includes some known column formats.
	fields := &ColumnsFromTshark{}
	err := fields.InitNoCache()
	assert.NoError(t, err)
	assert.True(t, len(fields.fields) > 0, "should parse at least one column format")

	// Verify known tokens are present
	tokenSet := make(map[string]bool)
	for _, f := range fields.fields {
		tokenSet[f.Field.Token] = true
	}
	assert.True(t, tokenSet["%m"], "should contain %%m (Number)")
	assert.True(t, tokenSet["%t"], "should contain %%t (Time)")
	assert.True(t, tokenSet["%s"], "should contain %%s (Source)")
	assert.True(t, tokenSet["%d"], "should contain %%d (Destination)")
	assert.True(t, tokenSet["%p"], "should contain %%p (Protocol)")
	assert.True(t, tokenSet["%i"], "should contain %%i (Information)")
}

func TestColumnsFromTshark_InitNoCache_AllFieldsHavePercentPrefix(t *testing.T) {
	fields := &ColumnsFromTshark{}
	err := fields.InitNoCache()
	assert.NoError(t, err)
	for _, f := range fields.fields {
		assert.True(t, strings.HasPrefix(f.Field.Token, "%"),
			"token %q should start with %%", f.Field.Token)
	}
}

func TestColumnsFromTshark_InitNoCache_AllFieldsHaveNames(t *testing.T) {
	fields := &ColumnsFromTshark{}
	err := fields.InitNoCache()
	assert.NoError(t, err)
	for _, f := range fields.fields {
		assert.NotEmpty(t, f.Name, "column for token %q should have a name", f.Field.Token)
	}
}

//======================================================================
// DefaultPsmlColumnSpec tests
//======================================================================

func TestDefaultPsmlColumnSpec_TokensValid(t *testing.T) {
	for _, col := range DefaultPsmlColumnSpec {
		assert.NotEmpty(t, col.Name)
		assert.NotEmpty(t, col.Field.Token)
		assert.True(t, strings.HasPrefix(col.Field.Token, "%"),
			"token %q should start with %%", col.Field.Token)
		assert.False(t, col.Hidden, "default columns should not be hidden")
	}
}

func TestDefaultPsmlColumnSpec_ExpectedOrder(t *testing.T) {
	expectedTokens := []string{"%m", "%t", "%s", "%d", "%p", "%L", "%i"}
	expectedNames := []string{"No.", "Time", "Source", "Dest", "Proto", "Length", "Info"}
	assert.Equal(t, len(expectedTokens), len(DefaultPsmlColumnSpec))
	for i, col := range DefaultPsmlColumnSpec {
		assert.Equal(t, expectedTokens[i], col.Field.Token, "index %d", i)
		assert.Equal(t, expectedNames[i], col.Name, "index %d", i)
	}
}

//======================================================================
// BuiltInColumnFormats tests
//======================================================================

func TestBuiltInColumnFormats_Count(t *testing.T) {
	// As of late 2020 there should be exactly 50 entries (%q through %t)
	assert.Equal(t, 50, len(BuiltInColumnFormats))
}

func TestBuiltInColumnFormats_AllHaveFieldSet(t *testing.T) {
	for key, info := range BuiltInColumnFormats {
		assert.Equal(t, key, info.Field, "Field should match key for %q", key)
	}
}

func TestBuiltInColumnFormats_TimeColumnsHaveDateTimeComparator(t *testing.T) {
	timeTokens := []string{"%Yt", "%YDOYt", "%At", "%Tt", "%Gt", "%Rt", "%t", "%Yut", "%YDOYut", "%Aut"}
	for _, tok := range timeTokens {
		info, ok := BuiltInColumnFormats[tok]
		assert.True(t, ok, "should have token %q", tok)
		assert.NotNil(t, info.Comparator, "time column %q should have a comparator", tok)
	}
}

func TestBuiltInColumnFormats_NumericColumnsHaveComparator(t *testing.T) {
	numericTokens := []string{"%q", "%B", "%m", "%L", "%D", "%S", "%E", "%F"}
	for _, tok := range numericTokens {
		info, ok := BuiltInColumnFormats[tok]
		assert.True(t, ok, "should have token %q", tok)
		assert.NotNil(t, info.Comparator, "numeric column %q should have a comparator", tok)
	}
}

func TestBuiltInColumnFormats_IPColumnsHaveIPComparator(t *testing.T) {
	ipTokens := []string{"%ud", "%und", "%uns", "%us", "%s"}
	for _, tok := range ipTokens {
		info, ok := BuiltInColumnFormats[tok]
		assert.True(t, ok, "should have token %q", tok)
		assert.NotNil(t, info.Comparator, "IP column %q should have a comparator", tok)
	}
}

//======================================================================
// Error sentinel values
//======================================================================

func TestInvalidCustomColumnError_Message(t *testing.T) {
	assert.Equal(t, "The custom column is invalid", InvalidCustomColumnError.Error())
}

func TestTsharkColumnsCacheOldError_Message(t *testing.T) {
	assert.Equal(t, "The cached tshark columns database is out of date", TsharkColumnsCacheOldError.Error())
}

func TestColumnsFormatError_Message(t *testing.T) {
	assert.Equal(t, "The supplied list of columns and names is invalid", ColumnsFormatError.Error())
}

//======================================================================
// GetPsmlColumnFormatFrom tests
// (these call getPsmlColumnFormatWithoutLock which reads from viper config.
// Without viper setup, it returns empty widths and thus uses defaults.)
//======================================================================

func TestGetPsmlColumnFormatFrom_NoConfig_ReturnsDefaults(t *testing.T) {
	// Without any viper configuration, ConfStringSlice returns [] so defaults are used
	result := GetPsmlColumnFormatFrom("nonexistent.key")
	assert.Equal(t, DefaultPsmlColumnSpec, result)
}

func TestGetPsmlColumnFormatFrom_EmptyKey_ReturnsDefaults(t *testing.T) {
	result := GetPsmlColumnFormatFrom("")
	assert.Equal(t, DefaultPsmlColumnSpec, result)
}

//======================================================================
// Local Variables:
// mode: Go
// fill-column: 78
// End:
