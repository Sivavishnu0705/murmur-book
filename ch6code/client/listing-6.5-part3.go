package main

import (
       "context"
       "net"
)

type dialer struct{ addr string }

// dial ignores the URL's host and connects to the lab address, so the URL can carry the
// real name (used for SNI and hostname verification) without any DNS setup.
func (d *dialer) dial(ctx context.Context, network, _ string) (net.Conn, error) {
       return (&net.Dialer{}).DialContext(ctx, network, d.addr)
}
