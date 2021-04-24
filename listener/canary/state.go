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
	"math/rand"
	"net"
	"sync"
	"time"
	"fmt"

	"github.com/honeytrap/honeytrap/listener/canary/tcp"
	"github.com/honeytrap/honeytrap/event"
)

// State defines a struct for holding connection data and address.
type State struct {
	// interface?
	c *Canary

	m sync.Mutex

	SrcHardwareAddr      net.HardwareAddr
	SrcIP   net.IP
	SrcPort uint16

	DestHardwareAddr      net.HardwareAddr
	DestIP   net.IP
	DestPort uint16

	ID uint32

	LastAcked uint32

	// /proc/net/tcp

	socket *Socket

	State SocketState
	// contains tx_queue
	// contains rx_queue

	// SND.UNA - send unacknowledged
	SendUnacknowledged uint32
	// SND.NXT - send next
	SendNext uint32
	// SND.WND - send window
	SendWindow uint32
	// SND.UP  - send urgent pointer
	SendUrgentPointer uint32

	// SND.WL1 - segment sequence number used for last window update
	SendWL1 uint32

	// SND.WL2 - segment acknowledgment number used for last window update
	SendWL2 uint32

	// ISS     - initial send sequence number
	InitialSendSequenceNumber uint32

	// RCV.NXT - receive next
	RecvNext uint32
	// RCV.WND - receive window
	ReceiveWindow uint16
	// RCV.UP  - receive urgent pointer
	ReceiveUrgentPointer uint32

	// IRS     - initial receive sequence number
	InitialReceiveSequenceNumber uint32

	t time.Time
}

func (s *State) write(data []byte) {
	// I think tstate should not write packets directly,
	// instead to write queue or buffer
	s.m.Lock()
	defer s.m.Unlock()

	s.c.send(s, data, tcp.PSH|tcp.ACK)
	s.SendNext += uint32(len(data))
}

func (s *State) close() {
	// I think tstate should not write packets directly,
	// instead to write queue or buffer
	s.m.Lock()
	defer s.m.Unlock()
	StateTableMutex.Lock()
	defer StateTableMutex.Unlock()

	// Queue this until all preceding SENDs have been segmentized, then
	// form a FIN segment and send it.  In any case, enter FIN-WAIT-1
	// state.
	s.c.send(s, []byte{}, tcp.FIN|tcp.ACK)
	s.SendNext++

	s.State = SocketFinWait1
}

// StateTable defines a slice of States type.
type StateTable [65535]*State

var (
	StateTableMutex sync.Mutex
)

// Add adds the state into the table.
func (st *StateTable) Add(state *State) {

	StateTableMutex.Lock()
	defer StateTableMutex.Unlock()

	for i := range *st {
		if (*st)[i] == nil {
			// slot not taken
		} else if (*st)[i].State == SocketTimeWait {
			// reuse socket timewait
		} else {
			continue
		}

		(*st)[i] = state
		return
	}

	now := time.Now()

	for i := range *st {
		if now.Sub((*st)[i].t) > 30*time.Second {
			// inactive
		} else {
			continue
		}

		(*st)[i] = state
		return
	}

	// we don't have enough space in the state table, and
	// there are no inactive entries
	panic("Statetable full")
}

// Expire removes inactive states from the table.
// We focus only on SynReceived states.
func (st *StateTable) Expire() {

	count := make( map[SocketState]int)
	now := time.Now()

	StateTableMutex.Lock()
	defer StateTableMutex.Unlock()

	for i := range *st {
		if (*st)[i] == nil {
			// empty slot
			continue
		}

		// Count the states we've seen
		if _, ok := count[(*st)[i].State]; ok {
			count[(*st)[i].State]++
		} else {
			count[(*st)[i].State] = 1
		}

		if now.Sub((*st)[i].t) > 30*time.Second  &&
		     (*st)[i].State == SocketSynReceived {
			// inactive
			//fmt.Println((*st)[i].SrcIP, (*st)[i].SrcPort, (*st)[i].DestIP, (*st)[i].DestPort)

			// Send the event to our subscribers 
			(*st)[i].c.events.Send(event.New(
				CanaryOptions,
				EventCategoryTCP,
				event.ConnectionTimeout,

				event.SourceHardwareAddr((*st)[i].SrcHardwareAddr),
				event.DestinationHardwareAddr((*st)[i].DestHardwareAddr),

				event.SourceIP((*st)[i].SrcIP),
				event.DestinationIP((*st)[i].DestIP),
				event.SourcePort((*st)[i].SrcPort),
				event.DestinationPort((*st)[i].DestPort),
				// event.Payload(buff[:n]),
			))

			// Remove the state
			(*st)[i] = nil
		}

	}

	fmt.Println("States counter: ", count)
}

// Get will return the state for the ip, port combination
func (st *StateTable) Get(SrcIP, DestIP net.IP, SrcPort, DestPort uint16) *State {
	StateTableMutex.Lock()
	defer StateTableMutex.Unlock()

	for _, state := range *st {
		if state == nil {
			continue
		}

		if state.SrcPort != SrcPort && state.DestPort != SrcPort {
			continue
		}

		if state.DestPort != DestPort && state.SrcPort != DestPort {
			continue
		}

		// comparing ipv6 with ipv4 now
		if !state.SrcIP.Equal(SrcIP) && !state.DestIP.Equal(SrcIP) {
			continue
		}

		if !state.DestIP.Equal(DestIP) && !state.SrcIP.Equal(DestIP) {
			continue
		}

		return state
	}

	return nil // state
}

func (st *StateTable) Remove(s *State) {
	StateTableMutex.Lock()
	defer StateTableMutex.Unlock()

	for i := range *st {
		if (*st)[i] != s {
			continue
		}

		(*st)[i] = nil
		break
	}
}

// NewState returns a new instance of a State.
func (c *Canary) NewState(src net.IP, srcPort uint16, dest net.IP, dstPort uint16) *State {
	return &State{
		c: c,

		SrcIP:   src,
		SrcPort: srcPort,

		DestIP:   dest,
		DestPort: dstPort,

		ID: rand.Uint32(),

		ReceiveWindow: 65535,

		RecvNext:                  0,
		InitialSendSequenceNumber: rand.Uint32(),

		t: time.Now(),

		m: sync.Mutex{},
	}
}
