package delayer

import (
	"log"
	"time"
)

type delayer struct {
	a time.Duration
	b time.Duration
}

func NewDelayer() *delayer {
	return &delayer{
		a: 0,
		b: time.Second,
	}
}

func (d *delayer) reset() *delayer {
	d.a, d.b = 0, time.Second
	return d
}

func (d *delayer) sleep() *delayer {
	if d.a >= 3*time.Minute {
		time.Sleep(3 * time.Minute)
	} else {
		time.Sleep(d.a)
		d.a, d.b = d.b, d.a+d.b
	}
	return d
}

func (d *delayer) ProcError(err error) bool {
	if err != nil {
		log.Println(err)
		d.sleep()
		return true
	}
	d.reset()
	return false
}
