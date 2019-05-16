package testhelpers

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// AssertCloseToNow asserts that the given time is within the given duration of the present time.
func AssertCloseToNow(t *testing.T, tme time.Time, dur time.Duration) {
	et := time.Now()

	// testify has comparisons in the works but not released as of this writng
	assert.True(t, et.Add(-1*dur).Before(tme),
		fmt.Sprintf("time %v earlier than expected %v", tme, et))
	assert.True(t, et.Add(dur).After(tme),
		fmt.Sprintf("time %v later than expected %v", tme, et))
}

// AssertWithin1MS asserts that the given times are within 1ms of each other.
func AssertWithin1MS(t *testing.T, tme1 time.Time, tme2 time.Time) {
	assert.True(t, tme1.Add(time.Millisecond*-1).Before(tme2), "times are not within 1MS")
	assert.True(t, tme1.Add(time.Millisecond*1).After(tme2), "times are not within 1MS")
}
