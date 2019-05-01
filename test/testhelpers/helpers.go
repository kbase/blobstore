package testhelpers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// AssertCloseToNow1S asserts that the given time is within one second of the present time.
func AssertCloseToNow1S(t *testing.T, tme time.Time) {
	et := time.Now()

	// testify has comparisons in the works but not released as of this wring
	assert.True(t, et.Add(time.Second*-1.).Before(tme), "time earlier than expected")
	assert.True(t, et.Add(time.Second*1.).After(tme), "time earlier than expected")
}
