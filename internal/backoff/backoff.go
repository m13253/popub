package backoff

import (
	"log"
	"math"
	"time"
)

type Retryer struct {
	retryCount uint64
}

func New() *Retryer {
	return &Retryer{
		retryCount: 0,
	}
}

func (d *Retryer) getDuration() time.Duration {
	if d.retryCount >= 12 {
		return 3 * time.Minute
	}
	return time.Duration(
		math.RoundToEven(
			math.Pow(1.618033988749895, float64(d.retryCount-1)) * float64(time.Second),
		),
	)
}

func (d *Retryer) reset() {
	d.retryCount = 0
}

func (d *Retryer) sleep() {
	if d.retryCount == 0 {
		d.retryCount++
		log.Printf("retry #1 after 0.0 seconds")
	} else {
		dur := d.getDuration()
		d.retryCount++
		log.Printf("retry #%d after %.1f seconds", d.retryCount, float64(dur)*1e-9)
		time.Sleep(dur)
	}
}

func (d *Retryer) ProcessError(err error) bool {
	if err != nil {
		log.Println(err)
		d.sleep()
		return true
	}
	d.reset()
	return false
}
