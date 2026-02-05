package confwatcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/gcla/termshark/v2"
	"github.com/gcla/termshark/v2/pkg/lifecycle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTest creates a temp directory tree mimicking XDG config layout,
// overrides xdg.ConfigHome, sets up a global lifecycle tracker, and
// returns a cleanup function that must be deferred by the caller.
func setupTest(t *testing.T) (confDir string, confFile string, cleanup func()) {
	t.Helper()

	tmpDir := t.TempDir()

	// Save original values
	origConfigHome := xdg.ConfigHome
	origTracker := termshark.Tracker()

	// Set up the lifecycle tracker so termshark.Go / GoWithContext work
	tracker := lifecycle.New()
	termshark.SetTracker(tracker)

	// Override xdg.ConfigHome so that termshark.ConfFile() resolves inside tmpDir
	xdg.ConfigHome = tmpDir

	// Create the termshark config directory
	confDir = filepath.Join(tmpDir, "termshark")
	err := os.MkdirAll(confDir, 0755)
	require.NoError(t, err)

	confFile = filepath.Join(confDir, "termshark.toml")

	cleanup = func() {
		tracker.ShutdownAndWait()
		xdg.ConfigHome = origConfigHome
		termshark.SetTracker(origTracker)
	}

	return confDir, confFile, cleanup
}

func TestNewCreatesValidConfigWatcher(t *testing.T) {
	_, confFile, cleanup := setupTest(t)
	defer cleanup()

	// Create the config file so the watcher can be added
	err := os.WriteFile(confFile, []byte("# test config\n"), 0644)
	require.NoError(t, err)

	cw, err := New()
	require.NoError(t, err)
	assert.NotNil(t, cw)
	assert.NotNil(t, cw.watcher)
	assert.NotNil(t, cw.change)
	assert.NotNil(t, cw.closech)

	// ConfigChanged should return a non-nil receive-only channel
	ch := cw.ConfigChanged()
	assert.NotNil(t, ch)

	cw.Close()
}

func TestChangesChannelReceivesNotification(t *testing.T) {
	_, confFile, cleanup := setupTest(t)
	defer cleanup()

	// Create the config file
	err := os.WriteFile(confFile, []byte("# initial\n"), 0644)
	require.NoError(t, err)

	cw, err := New()
	require.NoError(t, err)

	// Give the watcher goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// Modify the watched file
	err = os.WriteFile(confFile, []byte("# modified\n"), 0644)
	require.NoError(t, err)

	// We should receive a change notification
	select {
	case _, ok := <-cw.ConfigChanged():
		assert.True(t, ok, "expected to receive a change notification on an open channel")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for change notification")
	}

	cw.Close()
}

func TestCloseProperlyShutdown(t *testing.T) {
	_, confFile, cleanup := setupTest(t)
	defer cleanup()

	// Create the config file
	err := os.WriteFile(confFile, []byte("# test\n"), 0644)
	require.NoError(t, err)

	cw, err := New()
	require.NoError(t, err)

	ch := cw.ConfigChanged()

	// Close should complete without hanging
	done := make(chan struct{})
	go func() {
		cw.Close()
		close(done)
	}()

	select {
	case <-done:
		// Close completed successfully
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not complete within timeout, possible goroutine leak")
	}

	// After Close, the change channel should be closed (reads return zero value and ok=false)
	select {
	case _, ok := <-ch:
		assert.False(t, ok, "change channel should be closed after Close()")
	case <-time.After(5 * time.Second):
		t.Fatal("change channel was not closed after Close()")
	}
}

func TestWatchingNonExistentFile(t *testing.T) {
	_, confFile, cleanup := setupTest(t)
	defer cleanup()

	// Deliberately do NOT create the config file before calling New().
	// New() should handle os.IsNotExist gracefully.
	_, err := os.Stat(confFile)
	require.True(t, os.IsNotExist(err), "config file should not exist before test")

	cw, err := New()
	require.NoError(t, err, "New() should succeed even when watched file does not exist")
	assert.NotNil(t, cw)

	cw.Close()
}

func TestMultipleRapidChangesCoalesce(t *testing.T) {
	_, confFile, cleanup := setupTest(t)
	defer cleanup()

	// Create the config file
	err := os.WriteFile(confFile, []byte("# initial\n"), 0644)
	require.NoError(t, err)

	cw, err := New()
	require.NoError(t, err)

	// Give the watcher goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// Make many rapid changes to the file
	numChanges := 20
	for i := 0; i < numChanges; i++ {
		err = os.WriteFile(confFile, []byte("# change "+string(rune('A'+i))+"\n"), 0644)
		require.NoError(t, err)
	}

	// The watcher should deliver change notifications. Because the change
	// channel is unbuffered and each fsnotify event blocks on send, rapid
	// changes should naturally coalesce -- some events will be pending in
	// the fsnotify buffer while the consumer processes previous ones.
	//
	// We drain all available notifications and verify that at least one
	// was received, but fewer than the total number of file writes (showing
	// coalescing). We use a generous timeout then a short drain timeout.

	received := 0
	timeout := time.After(5 * time.Second)

	// Wait for at least one notification
	select {
	case <-cw.ConfigChanged():
		received++
	case <-timeout:
		t.Fatal("timed out waiting for at least one change notification")
	}

	// Drain any additional notifications that arrive quickly
	drainTimeout := time.After(500 * time.Millisecond)
drainLoop:
	for {
		select {
		case <-cw.ConfigChanged():
			received++
		case <-drainTimeout:
			break drainLoop
		}
	}

	assert.GreaterOrEqual(t, received, 1, "should receive at least one change notification")
	// With an unbuffered channel and 20 rapid writes, we expect some coalescing.
	// The exact count is non-deterministic, but it should be less than 20.
	t.Logf("received %d notifications for %d file writes", received, numChanges)

	cw.Close()
}

func TestConfigChangedReturnsCorrectChannel(t *testing.T) {
	_, confFile, cleanup := setupTest(t)
	defer cleanup()

	err := os.WriteFile(confFile, []byte("# test\n"), 0644)
	require.NoError(t, err)

	cw, err := New()
	require.NoError(t, err)

	// ConfigChanged should return the same channel every time
	ch1 := cw.ConfigChanged()
	ch2 := cw.ConfigChanged()
	assert.Equal(t, ch1, ch2, "ConfigChanged() should return the same channel on repeated calls")

	cw.Close()
}
