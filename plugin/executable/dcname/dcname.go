//dispatcher/plugin/executable/dcname/dcname.go
package dcname
 
import (
  "context"
  "github.com/IrineSistiana/mosdns/v3/dispatcher/handler"
  "github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/dnsutils"
  "github.com/miekg/dns"
)
 
const (
  PluginType = "dcname"
)
 
func init() {
  handler.RegInitFunc(PluginType, Init, func() interface{} { return new(Args) })
}
 
var _ handler.ExecutablePlugin = (*dcname)(nil)
 
type Args struct {
}
 
type dcname struct {
  *handler.BP
  args *Args
}
 
func Init(bp *handler.BP, args interface{}) (p handler.Plugin, err error) {
  return newDcname(bp, args.(*Args)), nil
}
 
func newDcname(bp *handler.BP, args *Args) handler.Plugin {
  return &dcname{
    BP:   bp,
    args: args,
  }
}
 
func (t *dcname) Exec(ctx context.Context, qCtx *handler.Context, next handler.ExecutableChainNode) error {
  if r := qCtx.R(); r != nil {
    q := qCtx.Q()
    if (len(q.Question) == 1 && len(r.Answer) >= 1) {
      qname := q.Question[0].Name
      qtype := q.Question[0].Qtype
      rname := r.Answer[0].Header().Name
      rtype := r.Answer[0].Header().Rrtype
      if ((qtype == dns.TypeA || qtype == dns.TypeAAAA) && qname == rname && rtype == dns.TypeCNAME) {
        var Answer2 []dns.RR
        for i := range r.Answer {
          var rr2 dns.RR
          switch rr := r.Answer[i].(type) {
          case *dns.A:
            rr2 = &dns.A{
              Hdr: dns.RR_Header{
                Name:   qname,
                Rrtype: dns.TypeA,
                Class:  dns.ClassINET,
                Ttl:    r.Answer[i].Header().Ttl,
              },
              A: rr.A,
            }
          case *dns.AAAA:
            rr2 = &dns.AAAA{
              Hdr: dns.RR_Header{
                Name:   qname,
                Rrtype: dns.TypeAAAA,
                Class:  dns.ClassINET,
                Ttl:    r.Answer[i].Header().Ttl,
              },
              AAAA: rr.AAAA,
            }
          default:
            continue
          }
          Answer2 = append(Answer2, rr2)
        }
        r.Answer = Answer2
      }
    }
  }
  return handler.ExecChainNode(ctx, qCtx, next)
}
