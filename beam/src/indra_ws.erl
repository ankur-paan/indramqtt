%% @doc RFC 6455 WebSocket framing for the MQTT-over-WebSocket edge listener.
%%
%% The edge does WS framing only: after the HTTP upgrade handshake (with
%% MQTT subprotocol negotiation) every binary message payload is raw MQTT
%% bytes taking the same {@link indra_conn} path as a TCP socket. The
%% kernel never sees WS framing.
%%
%% No standalone WS server library is vendored in this tree (the edge
%% builds with plain {@code erlc}, no fetched dependencies), so the
%% handshake and framing are implemented here directly on
%% {@code gen_tcp}. All cryptography (the {@code Sec-WebSocket-Accept}
%% hash) is delegated to the maintained OTP {@code crypto} and
%% {@code base64} applications; nothing cryptographic is hand-rolled.
%% TODO(parity): if a maintained Erlang WS server library becomes
%% available to the edge build, should the handshake/framing delegate to
%% it instead of this module?
%%
%% Failing closed: any malformed HTTP upgrade, any unmasked client frame,
%% any text frame, any oversize frame and any subprotocol other than
%% {@code mqtt} refuses or closes the connection; the edge never grants
%% access it cannot validate.
%% TODO(parity): does the reference accept a handshake with no
%% `Sec-WebSocket-Protocol' header (we refuse), or text frames carrying
%% MQTT (we close)? Both choices here are fail-closed guesses.
-module(indra_ws).

-export([default_path/0,
         default_port/0,
         default_wss_port/0,
         default_handshake_timeout_ms/0,
         default_max_frame_bytes/0,
         default_max_connections/0,
         max_http_bytes/0,
         accept_key/1,
         handshake/3,
         handshake/4,
         encode_binary/1,
         encode_pong/1,
         encode_close/0,
         feed/3]).

%% Default WS path. The example config sketches `/ws/mqtt'; the M1-01
%% task spec fixes the listener default to `/mqtt'; the spec wins and the
%% M1-03 schema owns the final value.
-define(DEFAULT_PATH, "/mqtt").
%% Default plaintext WS bind port (matches the example config bind).
-define(DEFAULT_PORT, 8083).
%% Default TLS WS (`wss') bind port. Adjacent to the plaintext WS port
%% (8083 + 1) following the same convention as MQTT/MQTTS (1883/8883
%% pair on a neighbouring port); the M1-03 schema owns the final value.
%% TODO(parity): confirm the default `wss' port and path with the M1-03
%% schema (this default is a fail-closed guess, disabled by default).
-define(DEFAULT_WSS_PORT, 8084).
%% Handshake deadline per connection. Same 5 s bound as the TLS handshake
%% in `indra_listener': bounds how long a half-open socket can linger
%% before its first byte is validated.
-define(DEFAULT_HANDSHAKE_TIMEOUT_MS, 5000).
%% Largest single WS frame payload (and largest reassembled fragmented
%% message) accepted per connection. 1 MiB caps per-frame edge memory far
%% below the 256 MiB MQTT maximum that would balloon the edge process,
%% while leaving headroom above the largest payload the load tests send.
-define(DEFAULT_MAX_FRAME_BYTES, 1048576).
%% Largest number of concurrent WS connections per listener. 10,000 bounds
%% acceptor memory on the same scale as the default per-user connection
%% quota; an operator may raise it explicitly via `{max_connections, N}'.
-define(DEFAULT_MAX_CONNECTIONS, 10000).
%% Largest HTTP upgrade head accepted. Upgrade headers are a request line
%% plus a handful of small fields; anything larger is abuse, refused
%% before more is allocated.
-define(MAX_HTTP_BYTES, 8192).
%% RFC 6455 section 1.3 magic GUID.
-define(WS_GUID, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").

-define(OP_CONT, 16#0).
-define(OP_TEXT, 16#1).
-define(OP_BINARY, 16#2).
-define(OP_CLOSE, 16#8).
-define(OP_PING, 16#9).
-define(OP_PONG, 16#A).

-type frag() :: none | {frag, binary(), non_neg_integer()}.
-type event() :: {binary, binary()} | {ping, binary()} | {pong, binary()} | {close, binary()}.

%% @doc Default WS path (`/mqtt').
-spec default_path() -> string().
default_path() -> ?DEFAULT_PATH.

%% @doc Default plaintext WS bind port (8083).
-spec default_port() -> inet:port_number().
default_port() -> ?DEFAULT_PORT.

%% @doc Default TLS WS (`wss') bind port (8084).
-spec default_wss_port() -> inet:port_number().
default_wss_port() -> ?DEFAULT_WSS_PORT.

%% @doc Default handshake deadline in milliseconds (5000).
-spec default_handshake_timeout_ms() -> pos_integer().
default_handshake_timeout_ms() -> ?DEFAULT_HANDSHAKE_TIMEOUT_MS.

%% @doc Default per-frame and per-message payload bound in bytes (1 MiB).
-spec default_max_frame_bytes() -> pos_integer().
default_max_frame_bytes() -> ?DEFAULT_MAX_FRAME_BYTES.

%% @doc Default concurrent-connection bound per WS listener (10000).
-spec default_max_connections() -> pos_integer().
default_max_connections() -> ?DEFAULT_MAX_CONNECTIONS.

%% @doc Largest HTTP upgrade head accepted in bytes (8192).
-spec max_http_bytes() -> pos_integer().
max_http_bytes() -> ?MAX_HTTP_BYTES.

%% @doc Compute the `Sec-WebSocket-Accept' value for a client key.
%%
%% The key is the raw header bytes the client sent; the hash runs in the
%% maintained OTP `crypto' application and the encoding in `base64'.
-spec accept_key(binary()) -> binary().
accept_key(Key) when is_binary(Key) ->
    base64:encode(crypto:hash(sha, <<Key/binary, ?WS_GUID>>)).

%% @doc Perform the server side of the WS opening handshake on an
%% accepted plaintext socket.
%%
%% Reads the HTTP upgrade request (bounded by {@link max_http_bytes/0}
%% and {@code TimeoutMs}), requires the configured path, the
%% {@code mqtt} subprotocol and RFC 6455 headers, then writes the 101
%% response selecting {@code mqtt}. Returns {@code ok} once the socket
%% carries WS frames; on any failure writes a 4xx/426 answer (when the
%% socket still allows it) and returns {@code {error, Reason}} so the
%% caller closes the socket. The socket must be passive
%% (`{active, false}') and owned by the caller.
-spec handshake(gen_tcp:socket(), string() | binary(), pos_integer()) ->
    ok | {error, term()}.
handshake(Sock, Path, TimeoutMs) ->
    handshake(Sock, tcp, Path, TimeoutMs).

%% @doc Perform the server side of the WS opening handshake on an
%% accepted socket of the given transport (`tcp' for plaintext,
%% `ssl' for a TLS socket that already completed its handshake).
%%
%% The HTTP upgrade, the `mqtt' subprotocol negotiation and every
%% bound are identical on both transports: TLS only changes which
%% driver reads and writes the bytes. TLS itself terminates in the
%% maintained OTP `ssl' application (never hand-rolled cryptography):
%% the offered versions are TLS 1.2 and TLS 1.3 (the OTP defaults,
%% which exclude TLS 1.0/1.1) with the OTP default cipher suite
%% posture. No client-certificate authentication is requested, matching
%% the TCP/TLS listener, which likewise verifies nothing client-side.
%% TODO(parity): does the reference negotiate ALPN (`http/1.1') or
%% validate SNI on the `wss' handshake (we do neither -- the same
%% posture as the TCP/TLS listener)?
-spec handshake(gen_tcp:socket() | ssl:sslsocket(), tcp | ssl,
                string() | binary(), pos_integer()) ->
    ok | {error, term()}.
handshake(Sock, Transport, Path, TimeoutMs) when is_list(Path) ->
    handshake(Sock, Transport, list_to_binary(Path), TimeoutMs);
handshake(Sock, Transport, Path, TimeoutMs)
  when is_binary(Path), (Transport =:= tcp orelse Transport =:= ssl) ->
    %% One deadline covers the whole upgrade request, so a client that
    %% trickles bytes cannot hold a connection slot past `TimeoutMs'.
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    case recv_head(Sock, Transport, <<>>, Deadline) of
        {ok, Head} ->
            check_request(Sock, Transport, Head, Path);
        {error, _} = Err ->
            Err
    end.

%% @doc Encode MQTT bytes (or an iolist of them) as one server binary
%% frame. Servers never mask. A batched run of MQTT packets rides one
%% frame; the client decodes the stream back to back.
-spec encode_binary(iodata()) -> iodata().
encode_binary(Data) ->
    Len = erlang:iolist_size(Data),
    [encode_header(16#82, Len), Data].

%% @doc Encode a pong reply for a ping payload. Servers never mask.
-spec encode_pong(binary()) -> binary().
encode_pong(Payload) when is_binary(Payload), byte_size(Payload) =< 125 ->
    <<16#8A, (byte_size(Payload)):8, Payload/binary>>.

%% @doc Encode an empty normal-closure frame. Servers never mask.
-spec encode_close() -> binary().
encode_close() ->
    <<16#88, 16#00>>.

%% @doc Feed raw socket bytes through the frame parser.
%%
%% Returns {@code {ok, Events, Rest, Frag}} where {@code Events} are the
%% data/control events in arrival order, {@code Rest} is the incomplete
%% frame tail to prepend to the next read, and {@code Frag} is the
%% continuation state to pass back in. Returns {@code {error, Reason}}
%% on any framing violation (unmasked frame, text frame, oversize
%% payload, bad continuation, nonzero reserved bits); the caller fails
%% the connection closed.
-spec feed(binary(), frag(), pos_integer()) ->
    {ok, [event()], binary(), frag()} | {error, term()}.
feed(Buf, Frag, Max) when is_binary(Buf), is_integer(Max), Max > 0 ->
    feed_loop(Buf, Frag, Max, []).

%%====================================================================
%% Handshake internals
%%====================================================================

recv_head(Sock, Transport, Acc, Deadline) ->
    case binary:match(Acc, <<"\r\n\r\n">>) of
        {Pos, 4} ->
            <<Head:Pos/binary, _/binary>> = Acc,
            {ok, Head};
        nomatch when byte_size(Acc) > ?MAX_HTTP_BYTES ->
            send_status(Sock, Transport, 400, "Request head too large"),
            {error, head_too_large};
        nomatch ->
            case Deadline - erlang:monotonic_time(millisecond) of
                Left when Left =< 0 ->
                    {error, handshake_timeout};
                Left ->
                    case ws_recv(Sock, Transport, 0, Left) of
                        {ok, More} ->
                            recv_head(Sock, Transport,
                                      <<Acc/binary, More/binary>>, Deadline);
                        {error, timeout} ->
                            {error, handshake_timeout};
                        {error, _} = Err ->
                            Err
                    end
            end
    end.

check_request(Sock, Transport, Head, Path) ->
    case binary:split(Head, <<"\r\n">>, [global]) of
        [RequestLine | HeaderLines] when RequestLine =/= <<>> ->
            case parse_request_line(RequestLine) of
                {ok, <<"GET">>, Target, <<"HTTP/1.1">>} ->
                    check_target(Sock, Transport, HeaderLines, Target, Path);
                {ok, _, _, _} ->
                    send_status(Sock, Transport, 400, "Only GET upgrades"),
                    {error, bad_method};
                {error, _} = Err ->
                    send_status(Sock, Transport, 400, "Malformed request line"),
                    Err
            end;
        _ ->
            send_status(Sock, Transport, 400, "Empty request"),
            {error, empty_request}
    end.

parse_request_line(Line) ->
    case binary:split(Line, <<" ">>, [global]) of
        [Method, Target, Version] when Method =/= <<>>, Target =/= <<>> ->
            {ok, Method, Target, Version};
        _ ->
            {error, malformed_request_line}
    end.

check_target(Sock, Transport, HeaderLines, Target, Path) ->
    Bare = hd(binary:split(Target, <<"?">>)),
    case Bare of
        Path ->
            check_headers(Sock, Transport, parse_headers(HeaderLines));
        _ ->
            send_status(Sock, Transport, 404, "Unknown WS path"),
            {error, wrong_path}
    end.

parse_headers(Lines) ->
    lists:foldl(fun parse_header/2, [], Lines).

parse_header(Line, Acc) ->
    case binary:split(Line, <<":">>) of
        [Name, Value] when Name =/= <<>> ->
            [{lower_bin(trim_bin(Name)), trim_bin(Value)} | Acc];
        _ ->
            Acc
    end.

check_headers(Sock, Transport, Headers) ->
    case header(<<"host">>, Headers) of
        undefined ->
            send_status(Sock, Transport, 400, "Host required"),
            {error, missing_host};
        _ ->
            check_upgrade(Sock, Transport, Headers)
    end.

check_upgrade(Sock, Transport, Headers) ->
    case has_token(header(<<"upgrade">>, Headers), <<"websocket">>) of
        true -> check_connection(Sock, Transport, Headers);
        false ->
            send_status(Sock, Transport, 400, "Upgrade: websocket required"),
            {error, missing_upgrade}
    end.

check_connection(Sock, Transport, Headers) ->
    case has_token(header(<<"connection">>, Headers), <<"upgrade">>) of
        true -> check_version(Sock, Transport, Headers);
        false ->
            send_status(Sock, Transport, 400, "Connection: Upgrade required"),
            {error, missing_connection}
    end.

check_version(Sock, Transport, Headers) ->
    case header(<<"sec-websocket-version">>, Headers) of
        <<"13">> -> check_key(Sock, Transport, Headers);
        _ ->
            catch ws_send(Sock, Transport,
                          ["HTTP/1.1 426 Upgrade Required\r\n",
                           "Sec-WebSocket-Version: 13\r\n",
                           "Content-Length: 0\r\n",
                           "Connection: close\r\n\r\n"]),
            {error, unsupported_version}
    end.

check_key(Sock, Transport, Headers) ->
    case header(<<"sec-websocket-key">>, Headers) of
        undefined ->
            send_status(Sock, Transport, 400, "Sec-WebSocket-Key required"),
            {error, missing_key};
        Key ->
            case valid_key(Key) of
                true -> check_protocol(Sock, Transport, Headers, Key);
                false ->
                    send_status(Sock, Transport, 400, "Bad Sec-WebSocket-Key"),
                    {error, bad_key}
            end
    end.

check_protocol(Sock, Transport, Headers, Key) ->
    case has_token(header(<<"sec-websocket-protocol">>, Headers), <<"mqtt">>) of
        true ->
            Accept = accept_key(trim_bin(Key)),
            catch ws_send(Sock, Transport,
                          ["HTTP/1.1 101 Switching Protocols\r\n",
                           "Upgrade: websocket\r\n",
                           "Connection: Upgrade\r\n",
                           "Sec-WebSocket-Accept: ", Accept, "\r\n",
                           "Sec-WebSocket-Protocol: mqtt\r\n\r\n"]),
            ok;
        false ->
            send_status(Sock, Transport, 400, "mqtt subprotocol required"),
            {error, missing_subprotocol}
    end.

valid_key(Key) ->
    try base64:decode(trim_bin(Key)) of
        Raw when byte_size(Raw) =:= 16 -> true;
        _ -> false
    catch
        _:_ -> false
    end.

header(Name, Headers) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, Value} -> Value;
        false -> undefined
    end.

%% @private True when a comma-separated header value holds Token
%% (case-insensitive match; callers pass the token lowercased, except
%% the `mqtt' subprotocol name which is matched exactly and therefore
%% lowercased by the caller contract of RFC 6455 + MQTT).
has_token(undefined, _Token) -> false;
has_token(Value, Token) ->
    Tokens = [lower_bin(trim_bin(T)) || T <- binary:split(Value, <<",">>, [global])],
    lists:member(Token, Tokens).

send_status(Sock, Transport, Code, Text) ->
    Reason = case Code of
        400 -> "Bad Request";
        404 -> "Not Found";
        426 -> "Upgrade Required";
        _ -> "Error"
    end,
    Body = list_to_binary(Text),
    catch ws_send(Sock, Transport,
                  ["HTTP/1.1 ", integer_to_list(Code), " ", Reason, "\r\n",
                   "Content-Length: ", integer_to_list(byte_size(Body)), "\r\n",
                   "Connection: close\r\n\r\n", Body]),
    ok.

%% @private Transport-aware send for the handshake phase (plaintext
%% `gen_tcp' or already-handshaked TLS `ssl').
ws_send(Sock, tcp, Data) -> gen_tcp:send(Sock, Data);
ws_send(Sock, ssl, Data) -> ssl:send(Sock, Data).

%% @private Transport-aware receive for the handshake phase.
ws_recv(Sock, tcp, Len, TimeoutMs) -> gen_tcp:recv(Sock, Len, TimeoutMs);
ws_recv(Sock, ssl, Len, TimeoutMs) -> ssl:recv(Sock, Len, TimeoutMs).

trim_bin(Bin) ->
    re:replace(Bin, "^[ \t]+|[ \t]+$", "", [global, {return, binary}]).

lower_bin(Bin) ->
    list_to_binary(string:lowercase(binary_to_list(Bin))).

%%====================================================================
%% Frame codec internals
%%====================================================================

feed_loop(Buf, Frag, Max, Acc) ->
    case parse_frame(Buf, Max) of
        {ok, {Fin, Op, Payload}, Rest} ->
            case apply_frame(Fin, Op, Payload, Frag, Max) of
                {event, Event, Frag1} ->
                    feed_loop(Rest, Frag1, Max, [Event | Acc]);
                {error, _} = Err ->
                    Err;
                %% Empty control with no event is impossible: every
                %% control opcode yields an event or an error.
                {ignore, Frag1} ->
                    feed_loop(Rest, Frag1, Max, Acc)
            end;
        {more} ->
            {ok, lists:reverse(Acc), Buf, Frag};
        {error, _} = Err ->
            Err
    end.

parse_frame(Buf, Max) ->
    case Buf of
        <<Fin:1, Rsv:3, Op:4, Mask:1, Len7:7, Rest/binary>> ->
            case Rsv of
                0 -> parse_length(Fin, Op, Mask, Len7, Rest, Max);
                _ -> {error, nonzero_reserved_bits}
            end;
        _ ->
            {more}
    end.

parse_length(Fin, Op, Mask, 126, Rest, Max) ->
    case Rest of
        <<Len:16/big, Tail/binary>> -> parse_body(Fin, Op, Mask, Len, Tail, Max);
        _ -> {more}
    end;
parse_length(Fin, Op, Mask, 127, Rest, Max) ->
    case Rest of
        <<Len:64/big, Tail/binary>> -> parse_body(Fin, Op, Mask, Len, Tail, Max);
        _ -> {more}
    end;
parse_length(Fin, Op, Mask, Len7, Rest, Max) ->
    parse_body(Fin, Op, Mask, Len7, Rest, Max).

parse_body(Fin, Op, Mask, Len, Tail, Max) ->
    IsControl = Op >= 16#8,
    case valid_op(Op) of
        false ->
            {error, {unknown_opcode, Op}};
        true when IsControl, (Fin =:= 0 orelse Len > 125) ->
            {error, bad_control_frame};
        true when Len > Max ->
            {error, frame_too_large};
        true when Mask =:= 0 ->
            %% RFC 6455 5.1: the server MUST close a connection that
            %% sends an unmasked frame.
            {error, unmasked_client_frame};
        true ->
            case Tail of
                <<MaskKey:4/binary, Body/binary>> when byte_size(Body) >= Len ->
                    <<Payload:Len/binary, Rest/binary>> = Body,
                    {ok, {Fin, Op, unmask(Payload, MaskKey)}, Rest};
                _ ->
                    {more}
            end
    end.

valid_op(?OP_CONT) -> true;
valid_op(?OP_TEXT) -> true;
valid_op(?OP_BINARY) -> true;
valid_op(?OP_CLOSE) -> true;
valid_op(?OP_PING) -> true;
valid_op(?OP_PONG) -> true;
valid_op(_) -> false.

apply_frame(_Fin, ?OP_PING, Payload, Frag, _Max) ->
    {event, {ping, Payload}, Frag};
apply_frame(_Fin, ?OP_PONG, Payload, Frag, _Max) ->
    {event, {pong, Payload}, Frag};
apply_frame(Fin, ?OP_CLOSE, Payload, Frag, _Max) when Fin =:= 1 ->
    {event, {close, Payload}, Frag};
apply_frame(_Fin, ?OP_CLOSE, _Payload, _Frag, _Max) ->
    {error, bad_control_frame};
apply_frame(_Fin, ?OP_TEXT, _Payload, _Frag, _Max) ->
    %% MQTT travels in binary messages only; a text frame is a
    %% protocol violation here, failed closed.
    {error, text_frame_rejected};
apply_frame(Fin, ?OP_BINARY, Payload, Frag, Max) ->
    case Frag of
        none when Fin =:= 1 ->
            {event, {binary, Payload}, none};
        none ->
            case byte_size(Payload) > Max of
                true -> {error, frame_too_large};
                false -> {ignore, {frag, Payload, byte_size(Payload)}}
            end;
        _ ->
            {error, fragmented_message_in_progress}
    end;
apply_frame(Fin, ?OP_CONT, Payload, Frag, Max) ->
    case Frag of
        none ->
            {error, unexpected_continuation};
        {frag, Acc, Size} ->
            Total = Size + byte_size(Payload),
            case Total > Max of
                true ->
                    {error, frame_too_large};
                false when Fin =:= 1 ->
                    {event, {binary, <<Acc/binary, Payload/binary>>}, none};
                false ->
                    {ignore, {frag, <<Acc/binary, Payload/binary>>, Total}}
            end
    end.

%% Every WS binary message unmasks here on the edge receive path, so
%% this is one linear `crypto:exor/2' NIF pass over an expanded mask
%% instead of one `<<Acc/binary, Byte>>' copy per input byte (which is
%% quadratic in the payload size). Bounded by the caller's `Max'
%% before this point; hashing and randomness stay in the maintained
%% OTP `crypto' application.
unmask(Payload, MaskKey) when is_binary(Payload), byte_size(MaskKey) =:= 4 ->
    Len = byte_size(Payload),
    Expanded = binary:copy(MaskKey, (Len + 3) div 4),
    <<Mask:Len/binary, _/binary>> = Expanded,
    crypto:exor(Payload, Mask).

encode_header(Prefix, Len) when Len =< 125 ->
    <<Prefix:8, Len:8>>;
encode_header(Prefix, Len) when Len =< 65535 ->
    <<Prefix:8, 126:8, Len:16/big>>;
encode_header(Prefix, Len) ->
    <<Prefix:8, 127:8, Len:64/big>>.
