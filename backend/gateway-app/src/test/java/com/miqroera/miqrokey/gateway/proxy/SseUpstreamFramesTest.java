package com.miqroera.miqrokey.gateway.proxy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * #34: the inbound SSE face must hand the client the JSON-RPC payload, not the
 * upstream's own SSE framing. These cases pin the unwrapping rules; the
 * end-to-end path (stream + message against a framed upstream) is covered in
 * {@link McpProxyContractTest}.
 */
class SseUpstreamFramesTest {

    private static List<String> payloads(String body, String contentType) {
        return SseUpstreamFrames.payloads(body.getBytes(StandardCharsets.UTF_8), contentType).stream()
                .map(bytes -> new String(bytes, StandardCharsets.UTF_8)).toList();
    }

    @Nested
    @DisplayName("plain JSON upstream (pre-#34 behaviour)")
    class PlainJson {

        @Test
        @DisplayName("a JSON body is relayed as one payload, unchanged")
        void passesThrough() {
            String body = "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 1,\n  \"result\": {}\n}";
            assertThat(payloads(body, "application/json")).containsExactly(body);
        }

        @Test
        @DisplayName("a JSON body is not mistaken for framing even without a content type")
        void passesThroughWithoutContentType() {
            String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
            assertThat(payloads(body, null)).containsExactly(body);
        }

        @Test
        @DisplayName("an empty body relays nothing (a notification's bare 202 is not a message)")
        void emptyBody() {
            assertThat(payloads("", "application/json")).isEmpty();
            assertThat(payloads("", null)).isEmpty();
        }
    }

    @Nested
    @DisplayName("upstream that answers in its own SSE framing")
    class FramedUpstream {

        @Test
        @DisplayName("one frame → the payload alone, without the `event:`/`data:` text")
        void unwrapsOneFrame() {
            String rpc = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}";
            String body = "event: message\ndata: " + rpc + "\n\n";
            assertThat(payloads(body, "text/event-stream;charset=UTF-8")).containsExactly(rpc);
        }

        @Test
        @DisplayName("several frames → one payload each, in order")
        void unwrapsEveryFrame() {
            String first = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}";
            String second = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
            String body = "event: message\ndata: " + first + "\n\nevent: message\ndata: " + second + "\n\n";
            assertThat(payloads(body, "text/event-stream")).containsExactly(first, second);
        }

        @Test
        @DisplayName("a multi-line data field is joined with \\n, as the SSE spec says")
        void joinsMultiLineData() {
            String body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\ndata: \"result\":{}}\n\n";
            assertThat(payloads(body, "text/event-stream"))
                    .containsExactly("{\"jsonrpc\":\"2.0\",\n\"id\":1,\n\"result\":{}}");
        }

        @Test
        @DisplayName("keep-alive comments and framing-only frames produce no payload")
        void skipsComments() {
            String rpc = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
            String body = ": ping\n\nevent: message\ndata: " + rpc + "\n\n: ping\n\n";
            assertThat(payloads(body, "text/event-stream")).containsExactly(rpc);
        }

        @Test
        @DisplayName("CRLF framing (some upstreams) is accepted")
        void acceptsCrlf() {
            String rpc = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
            assertThat(payloads("event: message\r\ndata: " + rpc + "\r\n\r\n", "text/event-stream"))
                    .containsExactly(rpc);
        }

        @Test
        @DisplayName("a trailing frame without the final blank line still counts")
        void toleratesMissingTrailingBlankLine() {
            String rpc = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
            assertThat(payloads("event: message\ndata: " + rpc, "text/event-stream")).containsExactly(rpc);
        }

        @Test
        @DisplayName("`data:` with no value carries nothing")
        void skipsEmptyData() {
            assertThat(payloads("event: message\ndata:\n\n", "text/event-stream")).isEmpty();
        }

        @Test
        @DisplayName("framing is sniffed when the upstream mislabels the body as JSON")
        void sniffsFramedBodyUnderJsonContentType() {
            String rpc = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
            assertThat(payloads("event: message\ndata: " + rpc + "\n\n", "application/json")).containsExactly(rpc);
        }

        @Test
        @DisplayName("a JSON body sent as text/event-stream (no framing) is kept whole")
        void jsonBodyUnderEventStreamType() {
            String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
            assertThat(payloads(body, "text/event-stream")).containsExactly(body);
        }
    }
}
