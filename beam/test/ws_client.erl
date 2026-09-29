%% @doc Real MQTT-over-WebSocket client library for edge tests.
%%
%% Reusable test client speaking RFC 6455 against
%% {@link indra_ws_listener}, used by {@link indra_ws_tests} instead of
%% crafting frames inline. Each handshake generates a fresh
%% `Sec-WebSocket-Key' via the maintained OTP `crypto' application and
%% verifies what the server returns: the status must be 101, the
%% `Sec-WebSocket-Accept' must equal `indra_ws:accept_key(Key)' for the
%% key just sent, and the `mqtt' subprotocol must be selected. Client
%% frames carry a fresh mask per frame; server frames are strictly
%% validated (unmasked, known opcodes, control length bounds,
%% no server fragmentation). All hashing and randomness run in OTP
%% `crypto' with `base64' encoding; nothing cryptographic is
%% hand-rolled.
-module(ws_client).

-export([handshake/2,
         handshake_raw/2,
         handshake_no_subprotocol/2,
         handshake_tls/2,
         handshake_raw_tls/2,
         handshake_no_subprotocol_tls/2,
         read_head/1,
         read_head/2,
         read_head_tls/1,
         read_head_tls/2,
         send_binary/2,
         send_binary_tls/2,
         send_frame/3,
         send_frame_tls/3,
         recv_binary/1,
         recv_binary/2,
         recv_binary_tls/1,
         recv_binary_tls/2,
         recv_event/1,
         recv_event/2,
         recv_event_tls/1,
         recv_event_tls/2,
         wait_closed/1,
         wait_closed/2,
         wait_closed_tls/1,
         wait_closed_tls/2,
         parse_server_frame/1,
         encode_masked/3,
         encode_masked/4]).

-define(TIMEOUT, 2000).

%% @doc Complete the WS upgrade on an already-connected socket and
%% verify the server's answer (101, accept key, mqtt subprotocol).
%% Returns `ok' once the socket carries WS frames.
-spec handshake(gen_tcp:socket(), string()) -> ok | {error, term()}.
handshake(Sock, Path) ->
    ensure_crypto(),
    Key = base64:encode(crypto:strong_rand_bytes(16)),
    ok = gen_tcp:send(Sock, handshake_req(Path, Key, true)),
    case read_head(Sock, <<>>) of
        {ok, Head} -> verify_handshake(Head, Key);
        {error, _} = Err -> Err
    end.

%% @doc Send a WS upgrade and return the raw response head without
%% verifying it (for negative tests asserting 4xx answers).
-spec handshake_raw(gen_tcp:socket(), string()) ->
    {ok, binary()} | {error, term()}.
handshake_raw(Sock, Path) ->
    ensure_crypto(),
    Key = base64:encode(crypto:strong_rand_bytes(16)),
    ok = gen_tcp:send(Sock, handshake_req(Path, Key, true)),
    read_head(Sock, <<>>).

%% @doc Send a WS upgrade without the subprotocol header and return
%% the raw response head (the server must refuse it).
-spec handshake_no_subprotocol(gen_tcp:socket(), string()) ->
    {ok, binary()} | {error, term()}.
handshake_no_subprotocol(Sock, Path) ->
    ensure_crypto(),
    Key = base64:encode(crypto:strong_rand_bytes(16)),
    ok = gen_tcp:send(Sock, handshake_req(Path, Key, false)),
    read_head(Sock, <<>>).

%% @doc Complete the WS upgrade on an already-connected TLS socket and
%% verify the server's answer (101, accept key, mqtt subprotocol).
%% The TLS handshake must already be done (see `ssl:connect/3'); the
%% HTTP upgrade then runs on the encrypted channel. Returns `ok' once
%% the socket carries WS frames.
-spec handshake_tls(ssl:sslsocket(), string()) -> ok | {error, term()}.
handshake_tls(Sock, Path) ->
    ensure_crypto(),
    Key = base64:encode(crypto:strong_rand_bytes(16)),
    ok = ssl:send(Sock, handshake_req(Path, Key, true)),
    case read_head_tls(Sock, <<>>) of
        {ok, Head} -> verify_handshake(Head, Key);
        {error, _} = Err -> Err
    end.

%% @doc Send a WS upgrade over TLS and return the raw response head
%% without verifying it (for negative tests asserting 4xx answers).
-spec handshake_raw_tls(ssl:sslsocket(), string()) ->
    {ok, binary()} | {error, term()}.
handshake_raw_tls(Sock, Path) ->
    ensure_crypto(),
    Key = base64:encode(crypto:strong_rand_bytes(16)),
    ok = ssl:send(Sock, handshake_req(Path, Key, true)),
    read_head_tls(Sock, <<>>).

%% @doc Send a WS upgrade over TLS without the subprotocol header and
%% return the raw response head (the server must refuse it).
-spec handshake_no_subprotocol_tls(ssl:sslsocket(), string()) ->
    {ok, binary()} | {error, term()}.
handshake_no_subprotocol_tls(Sock, Path) ->
    ensure_crypto(),
    Key = base64:encode(crypto:strong_rand_bytes(16)),
    ok = ssl:send(Sock, handshake_req(Path, Key, false)),
    read_head_tls(Sock, <<>>).

%% @doc Read one HTTP response head (up to the blank line).
-spec read_head(gen_tcp:socket()) -> {ok, binary()} | {error, term()}.
read_head(Sock) ->
    read_head(Sock, <<>>).

%% @private Accumulating reader with the test receive bound.
-spec read_head(gen_tcp:socket(), binary()) ->
    {ok, binary()} | {error, term()}.
read_head(Sock, Acc) ->
    case binary:match(Acc, <<"\r\n\r\n">>) of
        {Pos, 4} ->
            <<Head:Pos/binary, _/binary>> = Acc,
            {ok, Head};
        nomatch ->
            case gen_tcp:recv(Sock, 0, ?TIMEOUT) of
                {ok, More} -> read_head(Sock, <<Acc/binary, More/binary>>);
                {error, _} = Err -> Err
            end
    end.

%% @doc Read one HTTP response head over TLS (up to the blank line).
-spec read_head_tls(ssl:sslsocket()) -> {ok, binary()} | {error, term()}.
read_head_tls(Sock) ->
    read_head_tls(Sock, <<>>).

%% @private Accumulating TLS reader with the test receive bound.
-spec read_head_tls(ssl:sslsocket(), binary()) ->
    {ok, binary()} | {error, term()}.
read_head_tls(Sock, Acc) ->
    case binary:match(Acc, <<"\r\n\r\n">>) of
        {Pos, 4} ->
            <<Head:Pos/binary, _/binary>> = Acc,
            {ok, Head};
        nomatch ->
            case ssl:recv(Sock, 0, ?TIMEOUT) of
                {ok, More} -> read_head_tls(Sock, <<Acc/binary, More/binary>>);
                {error, _} = Err -> Err
            end
    end.

%% @doc Send one masked client binary message.
-spec send_binary(gen_tcp:socket(), iodata()) -> ok.
send_binary(Sock, Payload) ->
    send_frame(Sock, 16#2, Payload).

%% @doc Send one masked client binary message over TLS.
-spec send_binary_tls(ssl:sslsocket(), iodata()) -> ok.
send_binary_tls(Sock, Payload) ->
    send_frame_tls(Sock, 16#2, Payload).

%% @doc Send one masked client frame with the given opcode.
-spec send_frame(gen_tcp:socket(), 0..15, iodata()) -> ok.
send_frame(Sock, Op, Payload) ->
    ok = gen_tcp:send(Sock, encode_masked(Op, 1, Payload)).

%% @doc Send one masked client frame with the given opcode over TLS.
-spec send_frame_tls(ssl:sslsocket(), 0..15, iodata()) -> ok.
send_frame_tls(Sock, Op, Payload) ->
    ok = ssl:send(Sock, encode_masked(Op, 1, Payload)).

%% @doc Read one server binary message payload (validates the frame).
-spec recv_binary(gen_tcp:socket()) -> binary().
recv_binary(Sock) ->
    recv_binary(Sock, ?TIMEOUT).

%% @doc Read one server binary message payload with an explicit bound.
-spec recv_binary(gen_tcp:socket(), timeout()) -> binary().
recv_binary(Sock, Timeout) ->
    {ok, Bin} = gen_tcp:recv(Sock, 0, Timeout),
    {ok, {binary, Payload}, _} = parse_server_frame(Bin),
    Payload.

%% @doc Read one server binary message payload over TLS (validates the frame).
-spec recv_binary_tls(ssl:sslsocket()) -> binary().
recv_binary_tls(Sock) ->
    recv_binary_tls(Sock, ?TIMEOUT).

%% @doc Read one server binary message payload over TLS with an
%% explicit bound.
-spec recv_binary_tls(ssl:sslsocket(), timeout()) -> binary().
recv_binary_tls(Sock, Timeout) ->
    {ok, Bin} = ssl:recv(Sock, 0, Timeout),
    {ok, {binary, Payload}, _} = parse_server_frame(Bin),
    Payload.

%% @doc Read one server event (`{binary, Bin}', `{pong, Bin}' etc.).
-spec recv_event(gen_tcp:socket()) -> tuple().
recv_event(Sock) ->
    recv_event(Sock, ?TIMEOUT).

%% @doc Read one server event with an explicit bound.
-spec recv_event(gen_tcp:socket(), timeout()) -> tuple().
recv_event(Sock, Timeout) ->
    {ok, Bin} = gen_tcp:recv(Sock, 0, Timeout),
    {ok, Event, _} = parse_server_frame(Bin),
    Event.

%% @doc Read one server event over TLS (`{binary, Bin}', `{pong, Bin}' etc.).
-spec recv_event_tls(ssl:sslsocket()) -> tuple().
recv_event_tls(Sock) ->
    recv_event_tls(Sock, ?TIMEOUT).

%% @doc Read one server event over TLS with an explicit bound.
-spec recv_event_tls(ssl:sslsocket(), timeout()) -> tuple().
recv_event_tls(Sock, Timeout) ->
    {ok, Bin} = ssl:recv(Sock, 0, Timeout),
    {ok, Event, _} = parse_server_frame(Bin),
    Event.

%% @doc Wait until the server closes (close frame, then TCP close).
-spec wait_closed(gen_tcp:socket()) -> {error, closed} | term().
wait_closed(Sock) ->
    wait_closed(Sock, ?TIMEOUT).

%% @doc Wait until the server closes, with an explicit bound.
-spec wait_closed(gen_tcp:socket(), timeout()) ->
    {error, closed} | term().
wait_closed(Sock, Timeout) ->
    case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Bin} ->
            case parse_server_frame(Bin) of
                {ok, {close, _}, _} ->
                    %% The TCP FIN follows the close frame.
                    case gen_tcp:recv(Sock, 0, Timeout) of
                        {error, closed} -> {error, closed};
                        {ok, <<>>} -> {error, closed};
                        Other -> Other
                    end;
                {ok, _, _} ->
                    wait_closed(Sock, Timeout);
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Wait until the server closes the TLS connection (close frame,
%% then TLS close).
-spec wait_closed_tls(ssl:sslsocket()) -> {error, closed} | term().
wait_closed_tls(Sock) ->
    wait_closed_tls(Sock, ?TIMEOUT).

%% @doc Wait until the server closes the TLS connection, with an
%% explicit bound.
-spec wait_closed_tls(ssl:sslsocket(), timeout()) ->
    {error, closed} | term().
wait_closed_tls(Sock, Timeout) ->
    case ssl:recv(Sock, 0, Timeout) of
        {ok, Bin} ->
            case parse_server_frame(Bin) of
                {ok, {close, _}, _} ->
                    %% The TLS close follows the close frame.
                    case ssl:recv(Sock, 0, Timeout) of
                        {error, closed} -> {error, closed};
                        {ok, <<>>} -> {error, closed};
                        Other -> Other
                    end;
                {ok, _, _} ->
                    wait_closed_tls(Sock, Timeout);
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Parse one server frame (never masked).
%%
%% Validates what a real client must check: the frame must be
%% unmasked, reserved bits must be zero, the opcode must be known, a
%% control frame must be final with a payload of at most 125 bytes,
%% and only single-frame binary messages are accepted (the edge
%% always sends one frame per delivery). Returns
%% `{ok, Event, Rest}' or `{error, Reason}' so callers fail closed.
-spec parse_server_frame(binary()) ->
    {ok, {binary, binary()} | {ping, binary()} | {pong, binary()} |
         {close, binary()}, binary()} | {error, term()}.
parse_server_frame(<<Fin:1, Rsv:3, Op:4, Mask:1, Len7:7, Rest/binary>>) ->
    case {Rsv, Mask} of
        {0, 0} -> parse_server_len(Fin, Op, Len7, Rest);
        {_, 1} -> {error, masked_server_frame};
        _ -> {error, nonzero_reserved_bits}
    end;
parse_server_frame(_) ->
    {error, incomplete}.

%% @doc Encode one masked client frame with a fresh mask.
%%
%% Used both to send on the socket and to build parser inputs for the
%% `indra_ws:feed/3' unit tests. The mask comes from OTP `crypto'
%% per frame, as any real client generates it.
-spec encode_masked(0..15, 0..1, iodata()) -> binary().
encode_masked(Op, Fin, Payload) ->
    ensure_crypto(),
    encode_masked(Op, Fin, iolist_to_binary(Payload),
                  crypto:strong_rand_bytes(4)).

%% @doc Encode one masked client frame with an explicit mask key.
-spec encode_masked(0..15, 0..1, iodata(), binary()) -> binary().
encode_masked(Op, Fin, Payload, MaskKey)
  when is_binary(MaskKey), byte_size(MaskKey) =:= 4 ->
    ensure_crypto(),
    Raw = iolist_to_binary(Payload),
    Len = byte_size(Raw),
    Masked = mask_payload(Raw, MaskKey),
    Head = case Len of
        L when L =< 125 -> <<Fin:1, 0:3, Op:4, 1:1, L:7>>;
        L when L =< 65535 -> <<Fin:1, 0:3, Op:4, 1:1, 126:7, L:16/big>>;
        L -> <<Fin:1, 0:3, Op:4, 1:1, 127:7, L:64/big>>
    end,
    <<Head/binary, MaskKey/binary, Masked/binary>>.

%%====================================================================
%% Internals
%%====================================================================

ensure_crypto() ->
    _ = application:ensure_all_started(crypto),
    ok.

handshake_req(Path, Key, WithProtocol) ->
    Base = ["GET ", Path, " HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: ", Key, "\r\n",
            "Sec-WebSocket-Version: 13\r\n"],
    case WithProtocol of
        true -> [Base, "Sec-WebSocket-Protocol: mqtt\r\n\r\n"];
        false -> [Base, "\r\n"]
    end.

%% @private Verify the 101 answer against the key just sent.
verify_handshake(Head, Key) ->
    case Head of
        <<"HTTP/1.1 101", _/binary>> ->
            Expected = indra_ws:accept_key(Key),
            Headers = parse_head_headers(Head),
            case {find_header(<<"sec-websocket-accept">>, Headers),
                  find_header(<<"sec-websocket-protocol">>, Headers)} of
                {Expected, Proto} when Proto =/= undefined ->
                    case has_mqtt_token(Proto) of
                        true -> ok;
                        false -> {error, missing_subprotocol}
                    end;
                {Got, _} when Got =/= Expected ->
                    {error, bad_accept_key};
                {_, undefined} ->
                    {error, missing_subprotocol}
            end;
        _ ->
            {error, {unexpected_status, Head}}
    end.

parse_head_headers(Head) ->
    case binary:split(Head, <<"\r\n">>, [global]) of
        [_Status | Lines] ->
            lists:filtermap(fun parse_head_line/1, Lines);
        [] ->
            []
    end.

parse_head_line(Line) ->
    case binary:split(Line, <<":">>) of
        [Name, Value] when Name =/= <<>> ->
            {true, {lower_bin(trim_bin(Name)), trim_bin(Value)}};
        _ ->
            false
    end.

find_header(Name, Headers) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, Value} -> Value;
        false -> undefined
    end.

has_mqtt_token(Value) ->
    Tokens = [lower_bin(trim_bin(T))
              || T <- binary:split(Value, <<",">>, [global])],
    lists:member(<<"mqtt">>, Tokens).

trim_bin(Bin) ->
    re:replace(Bin, "^[ \t]+|[ \t]+$", "", [global, {return, binary}]).

lower_bin(Bin) ->
    list_to_binary(string:lowercase(binary_to_list(Bin))).

parse_server_len(Fin, Op, Len7, Rest) ->
    case Len7 of
        126 ->
            case Rest of
                <<L:16/big, Tail/binary>> -> parse_server_body(Fin, Op, L, Tail);
                _ -> {error, incomplete}
            end;
        127 ->
            case Rest of
                <<L:64/big, Tail/binary>> -> parse_server_body(Fin, Op, L, Tail);
                _ -> {error, incomplete}
            end;
        Small ->
            parse_server_body(Fin, Op, Small, Rest)
    end.

parse_server_body(Fin, Op, Len, Tail) ->
    IsControl = Op >= 16#8,
    ValidOp = Op =:= 16#2 orelse Op =:= 16#8 orelse Op =:= 16#9
        orelse Op =:= 16#A,
    case {ValidOp, IsControl, Fin, Len} of
        {false, _, _, _} ->
            {error, {unknown_opcode, Op}};
        {_, true, 0, _} ->
            {error, fragmented_control_frame};
        {_, true, _, L} when L > 125 ->
            {error, oversize_control_frame};
        _ when byte_size(Tail) < Len ->
            {error, incomplete};
        _ ->
            <<Payload:Len/binary, Rest/binary>> = Tail,
            server_event(Fin, Op, Payload, Rest)
    end.

server_event(1, 16#2, Payload, Rest) ->
    {ok, {binary, Payload}, Rest};
server_event(1, 16#9, Payload, Rest) ->
    {ok, {ping, Payload}, Rest};
server_event(1, 16#A, Payload, Rest) ->
    {ok, {pong, Payload}, Rest};
server_event(1, 16#8, Payload, Rest) ->
    {ok, {close, Payload}, Rest};
server_event(_, _, _, _) ->
    {error, fragmented_server_message}.

%% @private Mask bytes via one linear OTP `crypto' pass.
mask_payload(Payload, MaskKey) ->
    Len = byte_size(Payload),
    Expanded = binary:copy(MaskKey, (Len + 3) div 4),
    <<Mask:Len/binary, _/binary>> = Expanded,
    crypto:exor(Payload, Mask).
