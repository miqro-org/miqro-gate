package com.miqroera.miqrokey.gateway.proxy;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Normalizes the upstream body of the inbound SSE face (#34).
 *
 * <p>
 * The SSE transport relays one {@code message} event per upstream response, and
 * the client parses that event's {@code data} as JSON-RPC. That only holds
 * while the upstream answers with a bare JSON body. A <em>streamable-http</em>
 * upstream (verified against the reference MCP server) requires the caller to
 * accept {@code text/event-stream} and therefore answers in its own SSE framing
 * — relaying those bytes verbatim nests one SSE frame inside another and the
 * client can never parse the payload, so the handshake times out. This helper
 * turns the upstream body into the list of payloads the client should receive.
 * </p>
 *
 * <p>
 * Framing is detected from the response content type, with a content sniff as a
 * fallback for upstreams that mislabel it. A body that is not SSE-framed comes
 * back as a single payload, byte-for-byte unchanged — the pre-#34 behaviour,
 * kept for plain JSON upstreams.
 * </p>
 */
final class SseUpstreamFrames {

    private SseUpstreamFrames() {
    }

    /**
     * The JSON-RPC payloads carried by an upstream body: one entry per SSE
     * {@code data} payload when the body is SSE-framed, otherwise the body itself
     * as a single entry. Keep-alive comments, framing-only events and empty
     * payloads produce no entries; {@code event:} / {@code id:} / {@code retry:}
     * fields are consumed as framing and are not relayed (the client's vocabulary
     * on this face is {@code endpoint} / {@code message} / {@code error}, so the
     * gateway normalizes rather than forwarding the upstream's event names).
     */
    static List<byte[]> payloads(byte[] body, String contentType) {
        byte[] payload = body == null ? new byte[0] : body;
        if (payload.length == 0) {
            // Nothing came back — a notification's bare 202, for instance. There is
            // no JSON-RPC message for the client here, and an empty `message`
            // payload is worse than silence: standard clients parse the event data
            // and fail with "Unexpected end of JSON input".
            return List.of();
        }
        String text = new String(payload, StandardCharsets.UTF_8);
        boolean hint = isEventStream(contentType);
        boolean framed = looksFramed(text);
        if (!hint && !framed) {
            return List.of(payload);
        }
        List<byte[]> unwrapped = unwrap(text);
        // The content type claimed SSE but the body carries no frame at all: that
        // upstream is mislabelled, and relaying it whole beats dropping a reply
        // the caller is waiting for. A *framed* body that yields no payload really
        // did carry nothing (keep-alives only), so nothing is emitted.
        if (unwrapped.isEmpty() && !framed) {
            return List.of(payload);
        }
        return unwrapped;
    }

    /** The data payloads of an SSE-framed body, in order. */
    private static List<byte[]> unwrap(String text) {
        List<String> events = dataPayloads(text);
        List<byte[]> out = new ArrayList<>(events.size());
        for (String event : events) {
            out.add(event.getBytes(StandardCharsets.UTF_8));
        }
        return out;
    }

    private static boolean isEventStream(String contentType) {
        return contentType != null && contentType.toLowerCase().startsWith("text/event-stream");
    }

    /** First non-blank line looks like an SSE field → treat the body as framed. */
    private static boolean looksFramed(String text) {
        for (String line : normalize(text).split("\n", -1)) {
            if (line.isBlank()) {
                continue;
            }
            return line.startsWith("data:") || line.startsWith("event:") || line.charAt(0) == ':';
        }
        return false;
    }

    private static List<String> dataPayloads(String text) {
        List<String> payloads = new ArrayList<>();
        StringBuilder data = null;
        for (String line : normalize(text).split("\n", -1)) {
            if (line.isEmpty()) {
                // Blank line = end of event; SSE spec: the payload is the data
                // lines joined with \n (a trailing event without one still counts).
                data = dispatch(payloads, data);
                continue;
            }
            if (line.charAt(0) == ':') {
                continue;
            }
            int colon = line.indexOf(':');
            String field = colon < 0 ? line : line.substring(0, colon);
            if (!"data".equals(field)) {
                continue;
            }
            String value = colon < 0 ? "" : line.substring(colon + 1);
            if (!value.isEmpty() && value.charAt(0) == ' ') {
                value = value.substring(1);
            }
            if (data == null) {
                data = new StringBuilder();
            } else {
                data.append('\n');
            }
            data.append(value);
        }
        dispatch(payloads, data);
        return payloads;
    }

    private static StringBuilder dispatch(List<String> payloads, StringBuilder data) {
        if (data != null && !data.isEmpty()) {
            payloads.add(data.toString());
        }
        return null;
    }

    private static String normalize(String text) {
        return text.replace("\r\n", "\n").replace('\r', '\n');
    }
}
