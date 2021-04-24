// +build linux

// Copyright 2016-2019 DutchSec (https://dutchsec.com/)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package canary

import (
	"bytes"
	"context"
	//"fmt"
	"net"
	"time"

	"github.com/honeytrap/honeytrap/event"
)

var (
	// EventCategoryPortscan contains events for ssdp traffic
	EventCategoryPortscan = event.Category("portscan")
)


// KnockGroup groups multiple knocks
type KnockGroup struct {
	Start time.Time
	Last  time.Time

	SourceHardwareAddr      net.HardwareAddr
	DestinationHardwareAddr net.HardwareAddr

	SourceIP      net.IP
	DestinationIP net.IP

	Protocol Protocol

	Count int

	Knocks *UniqueSet
}

// KnockGrouper defines the interface for NewGroup function
type KnockGrouper interface {
	NewGroup() *KnockGroup
}

// KnockUDPPort struct contain UDP port knock metadata
type KnockUDPPort struct {
	SourceHardwareAddr      net.HardwareAddr
	DestinationHardwareAddr net.HardwareAddr

	SourceIP        net.IP
	DestinationIP   net.IP
	DestinationPort uint16
}

// NewGroup will return a new KnockGroup for UDP protocol
func (k KnockUDPPort) NewGroup() *KnockGroup {
	return &KnockGroup{
		Start:                   time.Now(),
		SourceHardwareAddr:      k.SourceHardwareAddr,
		DestinationHardwareAddr: k.DestinationHardwareAddr,
		SourceIP:                k.SourceIP,
		DestinationIP:           k.DestinationIP,
		Count:                   0,
		Knocks: NewUniqueSet(func(v1, v2 interface{}) bool {
			if _, ok := v1.(KnockUDPPort); !ok {
				return false
			}
			if _, ok := v2.(KnockUDPPort); !ok {
				return false
			}

			k1, k2 := v1.(KnockUDPPort), v2.(KnockUDPPort)
			return k1.DestinationPort == k2.DestinationPort
		}),
	}
}

// KnockTCPPort struct contain TCP port knock metadata
type KnockTCPPort struct {
	SourceHardwareAddr      net.HardwareAddr
	DestinationHardwareAddr net.HardwareAddr

	SourceIP        net.IP
	DestinationIP   net.IP
	DestinationPort uint16
}

// NewGroup will return a new KnockGroup for TCP protocol
func (k KnockTCPPort) NewGroup() *KnockGroup {
	return &KnockGroup{
		Start:                   time.Now(),
		SourceHardwareAddr:      k.SourceHardwareAddr,
		DestinationHardwareAddr: k.DestinationHardwareAddr,
		SourceIP:                k.SourceIP,
		DestinationIP:           k.DestinationIP,
		Protocol:                ProtocolTCP,
		Count:                   0,
		Knocks: NewUniqueSet(func(v1, v2 interface{}) bool {
			if _, ok := v1.(KnockTCPPort); !ok {
				return false
			}
			if _, ok := v2.(KnockTCPPort); !ok {
				return false
			}

			k1, k2 := v1.(KnockTCPPort), v2.(KnockTCPPort)
			return k1.DestinationPort == k2.DestinationPort
		}),
	}
}

// KnockICMP struct contain ICMP knock metadata
type KnockICMP struct {
	SourceHardwareAddr      net.HardwareAddr
	DestinationHardwareAddr net.HardwareAddr

	SourceIP      net.IP
	DestinationIP net.IP
}

// NewGroup will return a new KnockGroup for ICMP protocol
func (k KnockICMP) NewGroup() *KnockGroup {
	return &KnockGroup{
		Start:                   time.Now(),
		SourceHardwareAddr:      k.SourceHardwareAddr,
		DestinationHardwareAddr: k.DestinationHardwareAddr,
		SourceIP:                k.SourceIP,
		DestinationIP:           k.DestinationIP,
		Count:                   0,
		Protocol:                ProtocolICMP,
		Knocks: NewUniqueSet(func(v1, v2 interface{}) bool {
			if _, ok := v1.(KnockICMP); !ok {
				return false
			}
			if _, ok := v2.(KnockICMP); !ok {
				return false
			}

			_, _ = v1.(KnockICMP), v2.(KnockICMP)
			return true
		}),
	}
}

func (c *Canary) knockDetector(ctx context.Context) {
	c.knocks = NewUniqueSet(func(v1, v2 interface{}) bool {
		k1, k2 := v1.(*KnockGroup), v2.(*KnockGroup)
		return k1.Protocol == k2.Protocol &&
			bytes.Equal(k1.SourceHardwareAddr, k2.SourceHardwareAddr) &&
			bytes.Equal(k1.DestinationHardwareAddr, k2.DestinationHardwareAddr) &&
			k1.SourceIP.Equal(k2.SourceIP) &&
			k1.DestinationIP.Equal(k2.DestinationIP)
	})

	for {
		select {
		case <-ctx.Done():
			return
		case sk := <-c.knockChan:
			// Protecting the knocks set with knocksMutex
			c.knocksMutex.Lock()
			grouper := sk.(KnockGrouper)
			knock := c.knocks.Add(grouper.NewGroup()).(*KnockGroup)

			knock.Count++
			knock.Last = time.Now()

			knock.Knocks.Add(sk)

			c.knocksMutex.Unlock()
		/*
		case <-time.After(time.Second * 1):
			now := time.Now()

			c.knocks.Each(func(i int, v interface{}) {
				k := v.(*KnockGroup)

				// TODO(): make duration configurable
				// Remove / expire knock group if older than 600 secs
				// We also report the portscan in the events channel
				if k.Last.Add(time.Second * 600).Before(now) { // last + 600 < now <=> 600 < now - last =: age
					defer c.knocks.Remove(k)

					ports := make([]string, k.Knocks.Count())

					k.Knocks.Each(func(i int, v interface{}) {
						if k, ok := v.(KnockTCPPort); ok {
							ports[i] = fmt.Sprintf("tcp/%d", k.DestinationPort)
						} else if k, ok := v.(KnockUDPPort); ok {
							ports[i] = fmt.Sprintf("udp/%d", k.DestinationPort)
						} else if _, ok := v.(KnockICMP); ok {
							ports[i] = "icmp"
						}
					})

					c.events.Send(
						event.New(
							CanaryOptions,
							EventCategoryPortscan,
							event.SourceHardwareAddr(k.SourceHardwareAddr),
							event.DestinationHardwareAddr(k.DestinationHardwareAddr),
							event.SourceIP(k.SourceIP),
							event.DestinationIP(k.DestinationIP),
							event.Custom("portscan.ports", ports),
							event.Custom("portscan.knocks", k.Count),
							event.Custom("portscan.duration", k.Last.Sub(k.Start)),
						),
					)
				}
			})
		 */
		}
	}
}
