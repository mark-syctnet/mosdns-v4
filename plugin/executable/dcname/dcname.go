package dcname

import (
	"context"
	"github.com/IrineSistiana/mosdns/v4/coremain"
	"github.com/IrineSistiana/mosdns/v4/pkg/executable_seq"
	"github.com/IrineSistiana/mosdns/v4/pkg/query_context"
	"github.com/miekg/dns"
	"math/rand"
)

const (
	PluginType = "dcname"
)

func init() {
	coremain.RegNewPersetPluginFunc("dcname", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &dcname{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*dcname)(nil)

type dcname struct {
	*coremain.BP
}

func (t *dcname) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	q := qCtx.Q()
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	if r == nil {
		return nil
	}

	// Trim and shuffle answers for A and AAAA.
	switch qt := q.Question[0].Qtype; qt {
	case dns.TypeA, dns.TypeAAAA:
		rr := r.Answer[:0]
		for _, ar := range r.Answer {
			if ar.Header().Rrtype == qt {
				rr = append(rr, ar)
			}
			ar.Header().Name = q.Question[0].Name
		}

		rand.Shuffle(len(rr), func(i, j int) {
			rr[i], rr[j] = rr[j], rr[i]
		})

		r.Answer = rr
	}

	return nil
}
