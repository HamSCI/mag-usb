//=======================================================================
// test_ws_header_case.cpp
//
// HTTP header names are CASE-INSENSITIVE (RFC 9110 5.1), and so are the
// `Upgrade: websocket` and `Connection: Upgrade` tokens (RFC 6455 4.2.1).
//
// The handshake parser compared them with memcmp, so it accepted a client
// only if that client happened to capitalise exactly as the literals did.
// Every HTTP/2-era client lowercases header names -- Deno, Go's
// x/net/websocket, anything on nghttp2 -- and all of them were answered
// `400 Bad Request`, while a hand-written request using "Sec-WebSocket-Key:"
// was accepted.  Measured against mag-usb on a live station, 2026-09-30:
//
//     Canonical-Case headers  ->  HTTP/1.1 101 Switching Protocols
//     lowercase (as Deno)     ->  HTTP/1.1 400 Bad Request
//
// This exercises the comparison directly rather than over a socket, so it
// stays a unit test: no ports, no timing, nothing to flake.
//=======================================================================
#include <stdio.h>
#include <string.h>

#include "websocket.h"

namespace {

int failures = 0;

void chk(const char *what, bool got, bool want) {
    if (got == want) {
        printf("  ok    %s\n", what);
    } else {
        printf("  FAIL  %s (want %s, got %s)\n", what,
               want ? "true" : "false", got ? "true" : "false");
        failures++;
    }
}

}  // namespace

int main() {
    using websocket::ws_hdr_eq;

    // The exact bytes Deno sends, captured from the wire on 2026-09-30.
    chk("lowercase sec-websocket-key matches",
        ws_hdr_eq("sec-websocket-key", "Sec-WebSocket-Key", 17), true);
    chk("lowercase upgrade matches",
        ws_hdr_eq("upgrade", "Upgrade", 7), true);
    chk("lowercase connection matches",
        ws_hdr_eq("connection", "Connection", 10), true);
    chk("lowercase sec-websocket-version matches",
        ws_hdr_eq("sec-websocket-version", "Sec-WebSocket-Version", 21), true);

    // Canonical case must keep working -- this is what every existing client
    // sends, and breaking it to fix the above would be a poor trade.
    chk("canonical Sec-WebSocket-Key still matches",
        ws_hdr_eq("Sec-WebSocket-Key", "Sec-WebSocket-Key", 17), true);
    chk("SHOUTED header names match too",
        ws_hdr_eq("SEC-WEBSOCKET-KEY", "Sec-WebSocket-Key", 17), true);

    // Token VALUES are case-insensitive as well (RFC 6455 4.2.1).
    chk("Upgrade: WebSocket (mixed case value) matches",
        ws_hdr_eq("WebSocket", "websocket", 9), true);
    chk("Connection: upgrade (lowercase value) matches",
        ws_hdr_eq("upgrade", "Upgrade", 7), true);

    // ...and a genuinely different header must NOT match, or the fix would
    // accept anything of the right length.
    chk("a different header of equal length does not match",
        ws_hdr_eq("sec-websocket-kez", "Sec-WebSocket-Key", 17), false);
    chk("Origin is not Host",
        ws_hdr_eq("Origin", "Hostxx", 6), false);

    // Connection is a token LIST: `upgrade` may appear anywhere in it.
    using websocket::ws_hdr_has_token;
    auto conn = [](const char *v) {
        return ws_hdr_has_token(v, (uint32_t)strlen(v), "upgrade");
    };
    chk("Connection: Upgrade matches", conn("Upgrade"), true);
    chk("Connection: keep-alive, Upgrade (Firefox) matches",
        conn("keep-alive, Upgrade"), true);
    chk("Connection: Upgrade,keep-alive (no space) matches",
        conn("Upgrade,keep-alive"), true);
    chk("Connection: keep-alive alone does not match", conn("keep-alive"), false);
    chk("Connection: Upgraded is not the token upgrade", conn("Upgraded"), false);
    chk("Connection: x-upgrade is not the token upgrade", conn("x-upgrade"), false);
    chk("Connection: empty does not match", conn(""), false);

    if (failures) {
        printf("\n%d failure(s)\n", failures);
        return 1;
    }
    printf("\nall header-case checks passed\n");
    return 0;
}
