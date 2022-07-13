/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package transport

import (
	"context"
	"errors"
	"github.com/IrineSistiana/mosdns/v4/pkg/utils"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errEOL             = errors.New("end of life")
	errClosedTransport = errors.New("transport has been closed")

	nopLogger = zap.NewNop()
)

const (
	defaultIdleTimeout             = time.Second * 10
	defaultReadTimeout             = time.Second * 5
	defaultDialTimeout             = time.Second * 5
	defaultNoPipelineQueryTimeout  = time.Second * 5
	defaultNoConnReuseQueryTimeout = time.Second * 5
	defaultMaxConns                = 2
	defaultMaxQueryPerConn         = 65535

	writeTimeout = time.Second
)

// Transport is a DNS msg transport that supposes DNS over UDP,TCP,TLS.
// For UDP, it can reuse UDP sockets.
// For TCP and DoT, it implements RFC 7766 and supports pipeline mode and can handle
// out-of-order responses.
type Transport struct {
	// Nil logger disables logging.
	Logger *zap.Logger

	// The following funcs cannot be nil.
	// DialFunc specifies the method to dial a connection to the server.
	DialFunc func(ctx context.Context) (net.Conn, error)
	// WriteFunc specifies the method to write a wire dns msg to the connection
	// opened by the DialFunc.
	WriteFunc func(c io.Writer, m *dns.Msg) (int, error)
	// ReadFunc specifies the method to read a wire dns msg from the connection
	// opened by the DialFunc.
	ReadFunc func(c io.Reader) (*dns.Msg, int, error)

	// DialTimeout specifies the timeout for DialFunc.
	// Default is defaultDialTimeout.
	DialTimeout time.Duration

	// IdleTimeout controls the maximum idle time for each connection.
	// If IdleTimeout < 0, Transport will not reuse connections.
	// Default is defaultIdleTimeout.
	IdleTimeout time.Duration

	// If EnablePipeline is set and IdleTimeout > 0, the Transport will pipeline
	// queries as RFC 7766 6.2.1.1 suggested.
	EnablePipeline bool

	// MaxConns controls the maximum pipeline connections Transport can open.
	// It includes dialing connections.
	// Default is defaultMaxConns.
	// Each connection can handle no more than 65535 queries concurrently.
	// Typically, it is very rare reaching that limit.
	MaxConns int

	// MaxQueryPerConn controls the maximum queries that one pipeline connection
	// can handle. The connection will be closed if it reached the limit.
	// Default is defaultMaxQueryPerConn.
	MaxQueryPerConn uint16

	m                  sync.Mutex // protect following fields
	closed             bool
	pipelineConns      map[*pipelineConn]struct{}
	idledReusableConns map[*reusableConn]struct{}
	reusableConns      map[*reusableConn]struct{}
}

func (t *Transport) logger() *zap.Logger {
	if l := t.Logger; l != nil {
		return l
	}
	return nopLogger
}

func (t *Transport) idleTimeout() time.Duration {
	if t.IdleTimeout == 0 {
		return defaultIdleTimeout
	}
	return t.IdleTimeout
}

func (t *Transport) dialTimeout() time.Duration {
	if t := t.DialTimeout; t > 0 {
		return t
	}
	return defaultDialTimeout
}

func (t *Transport) maxConns() int {
	if n := t.MaxConns; n > 0 {
		return n
	}
	return defaultMaxConns
}

func (t *Transport) maxQueryPerConn() uint16 {
	if n := t.MaxQueryPerConn; n > 0 {
		return n
	}
	return defaultMaxQueryPerConn
}

func (t *Transport) isClosed() bool {
	t.m.Lock()
	closed := t.closed
	t.m.Unlock()
	return closed
}

func (t *Transport) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if t.isClosed() {
		return nil, errClosedTransport
	}

	if t.idleTimeout() <= 0 {
		return t.exchangeWithoutConnReuse(ctx, q)
	}

	if t.EnablePipeline {
		return t.exchangeWithPipelineConn(ctx, q)
	}

	return t.exchangeWithReusableConn(ctx, q)
}

func (t *Transport) CloseIdleConnections() {
	t.m.Lock()
	defer t.m.Unlock()

	for conn := range t.pipelineConns {
		if conn.queueLen() == 0 {
			delete(t.pipelineConns, conn)
			conn.closeWithErr(errEOL)
		}
	}
	for conn := range t.idledReusableConns {
		conn.close()
		delete(t.idledReusableConns, conn)
	}
}

// Close closes the Transport and all its active connections.
// All going queries will fail instantly. It always returns nil error.
func (t *Transport) Close() error {
	t.m.Lock()
	defer t.m.Unlock()

	t.closed = true
	for conn := range t.pipelineConns {
		delete(t.pipelineConns, conn)
		conn.closeWithErr(errClosedTransport)
	}
	for conn := range t.reusableConns {
		conn.close()
		delete(t.reusableConns, conn)
		delete(t.idledReusableConns, conn)
	}
	return nil
}

func (t *Transport) exchangeWithPipelineConn(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	attempt := 0
	for {
		attempt++
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		conn, isNewConn, qid, err := t.getPipelineConn()
		if err != nil {
			return nil, err
		}

		r, err := conn.exchange(ctx, m, qid)
		if err != nil {
			if !isNewConn && attempt <= 3 {
				t.logger().Debug("retrying pipeline connection", zap.NamedError("previous_err", err), zap.Int("attempt", attempt))
				continue
			}
			return nil, err
		}
		return r, nil
	}
}

func (t *Transport) exchangeWithoutConnReuse(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	conn, err := t.DialFunc(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(getContextDeadline(ctx, defaultNoConnReuseQueryTimeout))

	_, err = t.WriteFunc(conn, m)
	if err != nil {
		return nil, err
	}

	type result struct {
		m   *dns.Msg
		err error
	}

	resChan := make(chan *result, 1)
	go func() {
		b, _, err := t.ReadFunc(conn)
		resChan <- &result{b, err}
	}()

	select {
	case res := <-resChan:
		return res.m, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *Transport) exchangeWithReusableConn(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	type result struct {
		m   *dns.Msg
		err error
	}

	resChan := make(chan result, 1)
	go func() {
		for ctx.Err() == nil {
			c, reused, err := t.getReusableConn()
			if err != nil {
				resChan <- result{m: nil, err: err}
				return
			}

			b, err := c.exchange(q)
			if err != nil {
				t.releaseReusableConn(c, true)
				if reused {
					continue
				}
				resChan <- result{m: nil, err: err}
				return
			}

			t.releaseReusableConn(c, false)
			resChan <- result{m: b, err: nil}
			return
		}
	}()

	select {
	case res := <-resChan:
		return res.m, res.err

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *Transport) getReusableConnFromPool() (c *reusableConn, err error) {
	t.m.Lock()
	defer t.m.Unlock()

	if t.closed {
		return nil, errClosedTransport
	}

	for c = range t.idledReusableConns {
		delete(t.idledReusableConns, c)
		if ok := c.stopIdle(); ok {
			return c, nil
		} else { // idle timed out, this connection is closed by its inner timer.
			c.close()
		}
	}
	return nil, nil
}

// getReusableConn returns a *reusableConn.
// The idle time of *reusableConn is still within Transport.IdleTimeout
// but the inner socket may be unusable (closed, reset, etc.).
// The caller must call releaseReusableConn to release the reusableConn.
func (t *Transport) getReusableConn() (c *reusableConn, reused bool, err error) {
	c, err = t.getReusableConnFromPool()
	if err != nil {
		return nil, false, err
	}
	if c != nil {
		return c, true, nil
	}

	// Dial a new connection.
	ctx, cancel := context.WithTimeout(context.Background(), t.dialTimeout())
	defer cancel()
	conn, err := t.DialFunc(ctx)
	if err != nil {
		return nil, false, err
	}
	rc := newReusableConn(t, conn)

	t.m.Lock()
	if t.closed {
		t.m.Unlock()
		rc.close()
		return nil, false, errClosedTransport
	}
	if t.reusableConns == nil {
		t.reusableConns = make(map[*reusableConn]struct{})
	}
	t.reusableConns[rc] = struct{}{}
	t.m.Unlock()

	return rc, false, nil
}

func (t *Transport) releaseReusableConn(c *reusableConn, deadConn bool) {
	var closeConn bool

	t.m.Lock()
	if deadConn {
		delete(t.reusableConns, c)
	}
	if !t.closed && !deadConn {
		if t.idledReusableConns == nil {
			t.idledReusableConns = make(map[*reusableConn]struct{})
		}
		c.startIdle()
		t.idledReusableConns[c] = struct{}{}
	} else {
		closeConn = true
	}
	t.m.Unlock()

	if closeConn {
		c.close()
	}
}

func (t *Transport) getPipelineConn() (conn *pipelineConn, isNewConn bool, qid uint16, err error) {
	t.m.Lock()
	defer t.m.Unlock()

	if t.closed {
		return nil, false, 0, errClosedTransport
	}

	// Try to get an existing connection.
	for c := range t.pipelineConns {
		if c.isClosed() {
			delete(t.pipelineConns, c)
			continue
		}
		conn = c
		break
	}

	// Create a new connection.
	if conn == nil || (conn.queueLen() > 0 && len(t.pipelineConns) < t.maxConns()) {
		conn = newPipelineConn(t)
		isNewConn = true
		if t.pipelineConns == nil {
			t.pipelineConns = make(map[*pipelineConn]struct{})
		}
		t.pipelineConns[conn] = struct{}{}
	}

	qid, eol := conn.acquireQueueId()
	if eol { // This connection has served too many queries.
		// Note: the connection will close and clean up itself after its last query finished.
		// We can't close it here. Some queries may still on that connection.
		delete(t.pipelineConns, conn)
	}

	return conn, isNewConn, qid, nil
}

type pipelineConn struct {
	connId uint32 // Only for logging.

	t *Transport

	accumulateId uint32
	wg           sync.WaitGroup
	queueMu      sync.RWMutex // queue lock
	queue        map[uint16]chan *dns.Msg

	connMu             sync.Mutex
	dialFinishedNotify chan struct{}
	c                  net.Conn
	closeOnce          sync.Once
	closeNotify        chan struct{}
	closeErr           error
}

var pipelineConnIdCounter uint32

func newPipelineConn(t *Transport) *pipelineConn {
	c := &pipelineConn{
		t:                  t,
		dialFinishedNotify: make(chan struct{}),
		queue:              make(map[uint16]chan *dns.Msg),
		closeNotify:        make(chan struct{}),
		connId:             atomic.AddUint32(&pipelineConnIdCounter, 1),
	}

	go func() {
		dialCtx, cancel := context.WithTimeout(context.Background(), defaultDialTimeout)
		defer cancel()
		rc, err := c.t.DialFunc(dialCtx)
		if err != nil {
			c.closeWithErr(err)
			return
		}

		c.connMu.Lock()
		// pipelineConn is closed before dial is complete.
		if utils.ClosedChan(c.closeNotify) {
			c.connMu.Unlock()
			rc.Close()
			return
		}
		c.c = rc
		close(c.dialFinishedNotify)
		c.connMu.Unlock()

		c.readLoop()
	}()

	return c
}

// acquireQueueId returns a qid for the next exchange() call and an eol mark
// indicates the pipelineConn is end-of-life (can't' serve more requests).
// Note: exchange() must be called after acquireQueueId()
func (c *pipelineConn) acquireQueueId() (qid uint16, eol bool) {
	maxQid := uint32(c.t.maxQueryPerConn())
	id := atomic.AddUint32(&c.accumulateId, 1)
	if id > maxQid {
		panic("qid overflowed")
	}
	c.wg.Add(1)
	eol = id == maxQid
	if eol {
		go func() {
			c.wg.Wait()
			c.closeWithErr(errEOL)
		}()
	}
	return uint16(id), eol
}

func (c *pipelineConn) exchange(
	ctx context.Context,
	q *dns.Msg,
	qid uint16,
) (*dns.Msg, error) {
	defer c.wg.Done()

	select {
	case <-c.dialFinishedNotify:
	case <-c.closeNotify:
		return nil, c.closeErr
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// We have to modify the query ID, but as a writer we cannot modify q directly.
	// We make a copy of q.
	qCopy := shadowCopy(q)
	qCopy.Id = qid

	resChan := make(chan *dns.Msg, 1)
	c.queueMu.Lock()
	c.queue[qid] = resChan
	c.queueMu.Unlock()

	c.c.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := c.t.WriteFunc(c.c, qCopy)
	if err != nil {
		// Write error usually is fatal. Abort and close this connection.
		c.closeWithErr(err)
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-resChan:
		// Change the query id back.
		r.Id = q.Id
		return r, nil
	case <-c.closeNotify:
		return nil, c.closeErr
	}
}

func (c *pipelineConn) readLoop() {
	for {
		if c.queueLen() == 0 {
			c.c.SetReadDeadline(time.Now().Add(c.t.idleTimeout()))
		} else {
			c.c.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		}

		r, _, err := c.t.ReadFunc(c.c)
		if err != nil {
			c.closeWithErr(err) // abort this connection.
			return
		}

		c.queueMu.Lock()
		resChan, ok := c.queue[r.Id]
		if ok {
			delete(c.queue, r.Id)
		}
		c.queueMu.Unlock()

		if ok {
			select {
			case resChan <- r: // resChan has buffer
			default:
			}
		}
	}
}

func (c *pipelineConn) isClosed() bool {
	return utils.ClosedChan(c.closeNotify)
}

func (c *pipelineConn) closeWithErr(err error) {
	c.closeOnce.Do(func() {
		c.connMu.Lock()
		defer c.connMu.Unlock()

		c.closeErr = err
		close(c.closeNotify)

		if c.c != nil {
			c.c.Close()
		}

		c.t.logger().Debug("connection closed", zap.Uint32("id", c.connId), zap.Error(err))
	})
}

func (c *pipelineConn) queueLen() int {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	return len(c.queue)
}

type reusableConn struct {
	t *Transport
	c net.Conn

	m                sync.Mutex
	closed           bool
	closeErr         error
	idleTimeoutTimer *time.Timer
}

func newReusableConn(t *Transport, c net.Conn) *reusableConn {
	nc := &reusableConn{
		t: t,
		c: c,
	}
	return nc
}

func (rc *reusableConn) exchange(m *dns.Msg) (*dns.Msg, error) {
	rc.c.SetDeadline(time.Now().Add(defaultNoPipelineQueryTimeout))
	if _, err := rc.t.WriteFunc(rc.c, m); err != nil {
		return nil, err
	}
	b, _, err := rc.t.ReadFunc(rc.c)
	return b, err
}

// If stopIdle returns false, then nc is closed by the
// idle timer.
func (rc *reusableConn) stopIdle() bool {
	rc.m.Lock()
	defer rc.m.Unlock()
	if rc.closed {
		return false
	}
	if rc.idleTimeoutTimer != nil {
		return rc.idleTimeoutTimer.Stop()
	}
	return true
}

func (rc *reusableConn) startIdle() {
	rc.m.Lock()
	defer rc.m.Unlock()

	if rc.closed {
		return
	}

	if rc.idleTimeoutTimer != nil {
		rc.idleTimeoutTimer.Reset(rc.t.idleTimeout())
	} else {
		rc.idleTimeoutTimer = time.AfterFunc(rc.t.idleTimeout(), func() {
			rc.close()
		})
	}
}

func (rc *reusableConn) close() {
	rc.m.Lock()
	defer rc.m.Unlock()

	if !rc.closed {
		if rc.idleTimeoutTimer != nil {
			rc.idleTimeoutTimer.Stop()
		}
		rc.c.Close()
		rc.closed = true
	}
}
