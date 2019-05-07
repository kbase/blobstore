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
	assert.True(t, et.Add(time.Second*-1).Before(tme), "time earlier than expected")
	assert.True(t, et.Add(time.Second*1).After(tme), "time later than expected")
}

// AssertWithin1MS asserts that the given times are within 1ms of each other.
func AssertWithin1MS(t *testing.T, tme1 time.Time, tme2 time.Time) {
	assert.True(t, tme1.Add(time.Millisecond*-1).Before(tme2), "times are not within 1MS")
	assert.True(t, tme1.Add(time.Millisecond*1).After(tme2), "times are not within 1MS")
}
