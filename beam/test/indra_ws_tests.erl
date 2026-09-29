%% @doc EUnit tests for MQTT over WebSocket (`indra_ws_listener').
%%
%% Self-terminating integration coverage: the WS listener binds an
%% ephemeral port, the test client completes a real RFC 6455 upgrade
%% (with `mqtt' subprotocol negotiation) over a real TCP socket, and
%% the resulting connection completes the CONNECT -> CONNACK handshake
%% against {@link mock_broker} exactly like a TCP connection. Cross
%% tests run a WS listener and a TCP listener against the same mock
%% broker and prove deliveries flow both ways. Nothing outlives the test.
%%
%% The integration tests speak through the reusable {@link ws_client}
%% library: a fresh `Sec-WebSocket-Key' per connection, verification
%% of the server's `Sec-WebSocket-Accept' and `mqtt' subprotocol
%% selection, a fresh client mask per frame, and strict validation of
%% server frames. A browser or WS-capable MQTT client connects the
%% same way.
-module(indra_ws_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).
%% RFC 6455 section 1.3 worked example, used only as a unit vector
%% for `indra_ws:accept_key/1' below; integration handshakes use
%% fresh keys inside {@link ws_client}.
-define(WS_KEY, <<"dGhlIHNhbXBsZSBub25jZQ==">>).
%% RFC 6455 section 1.3 worked example.
-define(WS_ACCEPT, <<"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=">>).

%%====================================================================
%% Frame codec unit tests (no sockets)
%%====================================================================

accept_key_vector_test() ->
    ?assertEqual(?WS_ACCEPT, indra_ws:accept_key(?WS_KEY)).

server_binary_roundtrip_test() ->
    Payload = <<"hello mqtt">>,
    Wire = iolist_to_binary(indra_ws:encode_binary(Payload)),
    %% Server frames are unmasked; a client-style masked copy decodes
    %% to the same payload through the server-side parser.
    Client = ws_client:encode_masked(16#2, 1, Payload),
    {ok, [{binary, Payload}], <<>>, none} =
        indra_ws:feed(Client, none, 1048576),
    %% The server's own encoding parses back through the header rules
    %% (mask bit is checked only for client input, so parse it raw).
    <<16#82, Len:8, Payload:Len/binary>> = Wire,
    ok.

masked_binary_decodes_test() ->
    Payload = <<1, 2, 3, 4, 5>>,
    Frame = ws_client:encode_masked(16#2, 1, Payload),
    {ok, [{binary, Payload}], <<>>, none} =
        indra_ws:feed(Frame, none, 1048576).

unmasked_client_frame_rejected_test() ->
    Frame = <<16#82, 16#05, "hello">>,
    ?assertMatch({error, unmasked_client_frame},
                 indra_ws:feed(Frame, none, 1048576)).

text_frame_rejected_test() ->
    Frame = ws_client:encode_masked(16#1, 1, <<"mqtt">>),
    ?assertMatch({error, text_frame_rejected},
                 indra_ws:feed(Frame, none, 1048576)).

fragmented_message_reassembles_test() ->
    F1 = ws_client:encode_masked(16#2, 0, <<"hel">>),
    F2 = ws_client:encode_masked(16#0, 1, <<"lo">>),
    {ok, [], Rest, Frag} = indra_ws:feed(F1, none, 1048576),
    ?assertEqual(<<>>, Rest),
    ?assertNotEqual(none, Frag),
    {ok, [{binary, <<"hello">>}], <<>>, none} =
        indra_ws:feed(<<Rest/binary, F2/binary>>, Frag, 1048576).

oversize_frame_rejected_test() ->
    Big = binary:copy(<<"x">>, 200),
    Frame = ws_client:encode_masked(16#2, 1, Big),
    ?assertMatch({error, frame_too_large},
                 indra_ws:feed(Frame, none, 100)).

split_frame_across_reads_test() ->
    Frame = ws_client:encode_masked(16#2, 1, <<"split">>),
    N = byte_size(Frame) - 2,
    <<Head:N/binary, Tail/binary>> = Frame,
    {ok, [], Got, none} = indra_ws:feed(Head, none, 1048576),
    ?assertEqual(Head, Got),
    {ok, [{binary, <<"split">>}], <<>>, none} =
        indra_ws:feed(<<Got/binary, Tail/binary>>, none, 1048576).

ping_pong_close_events_test() ->
    Ping = ws_client:encode_masked(16#9, 1, <<"hi">>),
    {ok, [{ping, <<"hi">>}], <<>>, none} =
        indra_ws:feed(Ping, none, 1048576),
    Pong = ws_client:encode_masked(16#A, 1, <<"hi">>),
    {ok, [{pong, <<"hi">>}], <<>>, none} =
        indra_ws:feed(Pong, none, 1048576),
    Close = ws_client:encode_masked(16#8, 1, <<>>),
    {ok, [{close, <<>>}], <<>>, none} =
        indra_ws:feed(Close, none, 1048576),
    ?assertEqual(<<16#8A, 16#02, "hi">>, indra_ws:encode_pong(<<"hi">>)),
    ?assertEqual(<<16#88, 16#00>>, indra_ws:encode_close()).

%%====================================================================
%% Listener integration tests (real sockets, mock broker as the core)
%%====================================================================

ws_handshake_selects_mqtt_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_ws_listener:start_link([{port, 0},
                                                  {conn, [{broker, Mock}]}]),
    try
        {ok, Port} = indra_ws_listener:get_port(Listener),
        {ok, Sock} = gen_tcp:connect("127.0.0.1", Port,
                                     [binary, {packet, raw}, {active, false}],
                                     2000),
        try
            ok = ws_client:handshake(Sock, "/mqtt"),
            %% The listener answers 101 and selects mqtt; the mock
            %% broker has seen nothing yet (no MQTT bytes sent).
            ?assertEqual([], mock_broker:sent(Mock))
        after
            gen_tcp:close(Sock)
        end
    after
        indra_ws_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

ws_wrong_path_rejected_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_ws_listener:start_link([{port, 0},
                                                  {conn, [{broker, Mock}]}]),
    try
        {ok, Port} = indra_ws_listener:get_port(Listener),
        {ok, Sock} = gen_tcp:connect("127.0.0.1", Port,
                                     [binary, {packet, raw}, {active, false}],
                                     2000),
        try
            Resp = ws_client:handshake_raw(Sock, "/bad"),
            ?assertMatch({ok, <<"HTTP/1.1 404", _/binary>>}, Resp),
            %% Failed closed: the socket is gone.
            ?assertMatch({error, closed},
                         gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT))
        after
            catch gen_tcp:close(Sock)
        end
    after
        indra_ws_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

ws_missing_subprotocol_refused_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_ws_listener:start_link([{port, 0},
                                                  {conn, [{broker, Mock}]}]),
    try
        {ok, Port} = indra_ws_listener:get_port(Listener),
        {ok, Sock} = gen_tcp:connect("127.0.0.1", Port,
                                     [binary, {packet, raw}, {active, false}],
                                     2000),
        try
            ?assertMatch({ok, <<"HTTP/1.1 400", _/binary>>},
                         ws_client:handshake_no_subprotocol(Sock, "/mqtt")),
            ?assertMatch({error, closed},
                         gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT))
        after
            catch gen_tcp:close(Sock)
        end
    after
        indra_ws_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc WS connect carries the same bind metadata as TCP: the kernel
%% enforces wrong-password, quota and ban decisions on identical input,
%% so per-user quotas apply equally to both transports.
ws_bind_matches_tcp_bind_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Tcp} = indra_listener:start_link([{port, 0},
                                           {conn, [{broker, Mock}]}]),
    {ok, Ws} = indra_ws_listener:start_link([{port, 0},
                                             {conn, [{broker, Mock}]}]),
    try
        {ok, TcpPort} = indra_listener:get_port(Tcp),
        {ok, WsPort} = indra_ws_listener:get_port(Ws),
        {ok, TSock} = gen_tcp:connect("127.0.0.1", TcpPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        {ok, WSock} = gen_tcp:connect("127.0.0.1", WsPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        try
            Connect = connect_packet(<<"quota-user">>, {<<"quota-user">>, <<"pw9">>},
                                       true, 60),
            ok = gen_tcp:send(TSock, Connect),
            ok = ws_client:handshake(WSock, "/mqtt"),
            ok = ws_client:send_binary(WSock, Connect),
            [TBind, WBind] = wait_binds(Mock, <<"quota-user">>, 2, 40),
            {ok, TMeta} = indra_brokerlink:decode_bind_meta(maps:get(meta, TBind)),
            {ok, WMeta} = indra_brokerlink:decode_bind_meta(maps:get(meta, WBind)),
            ?assertEqual(maps:get(client_id, TMeta), maps:get(client_id, WMeta)),
            ?assertEqual(maps:get(username, TMeta), maps:get(username, WMeta)),
            ?assertEqual(maps:get(password, TMeta), maps:get(password, WMeta)),
            ?assertEqual(maps:get(username, WMeta), <<"quota-user">>),
            ?assertEqual(maps:get(password, WMeta), <<"pw9">>)
        after
            gen_tcp:close(TSock),
            gen_tcp:close(WSock)
        end
    after
        indra_ws_listener:stop(Ws),
        indra_listener:stop(Tcp),
        mock_broker:stop(Mock)
    end.

%% @doc A WS publish reaches a TCP subscriber and a TCP publish reaches
%% a WS subscriber (QoS 0 and QoS 1), through the real listeners and
%% the broker path.
ws_tcp_cross_delivery_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Tcp} = indra_listener:start_link([{port, 0},
                                           {conn, [{broker, Mock}]}]),
    {ok, Ws} = indra_ws_listener:start_link([{port, 0},
                                             {conn, [{broker, Mock}]}]),
    try
        {ok, TcpPort} = indra_listener:get_port(Tcp),
        {ok, WsPort} = indra_ws_listener:get_port(Ws),
        {ok, TSock} = gen_tcp:connect("127.0.0.1", TcpPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        {ok, WSock} = gen_tcp:connect("127.0.0.1", WsPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        try
            {TConn, _} = tcp_handshake(TSock, Mock, <<"tcp-sub">>),
            {WConn, _} = ws_mqtt_handshake(WSock, Mock, <<"ws-sub">>),
            %% Both subscribe to the same topic.
            ok = gen_tcp:send(TSock, subscribe_packet(7, [{<<"x/y">>, 1}])),
            TSub = wait_frame(Mock, TConn, 16#0030),
            {ok, TSubMeta} = indra_brokerlink:decode_subscribe_meta(maps:get(meta, TSub)),
            ?assertEqual(7, maps:get(packet_id, TSubMeta)),
            ok = ws_client:send_binary(WSock, subscribe_packet(9, [{<<"x/y">>, 1}])),
            WSub = wait_frame(Mock, WConn, 16#0030),
            {ok, WSubMeta} = indra_brokerlink:decode_subscribe_meta(maps:get(meta, WSub)),
            ?assertEqual(9, maps:get(packet_id, WSubMeta)),
            ok = indra_conn:broker_frame(
                   TConn, #{opcode => 16#0031},
                   indra_brokerlink:encode_suback_meta(7, [1]), <<>>),
            ?assertEqual(<<16#90, 16#03, 16#00, 16#07, 16#01>>,
                         recv_exact(TSock, 5)),
            ok = indra_conn:broker_frame(
                   WConn, #{opcode => 16#0031},
                   indra_brokerlink:encode_suback_meta(9, [1]), <<>>),
            ?assertEqual(<<16#90, 16#03, 16#00, 16#09, 16#01>>,
                         ws_client:recv_binary(WSock)),
            %% WS publishes QoS 0: TCP receives it.
            ok = ws_client:send_binary(WSock, publish_packet(<<"x/y">>, 0, 16#30, <<"ws-hi">>)),
            WPub = wait_frame(Mock, WConn, 16#0020),
            {ok, WPubMeta} = indra_brokerlink:decode_publish_meta(maps:get(meta, WPub)),
            ?assertEqual(<<"x/y">>, maps:get(topic, WPubMeta)),
            Out0 = indra_brokerlink:encode_publish_meta(<<"x/y">>, 0, 0, false, false),
            ok = indra_conn:broker_frame(
                   TConn, #{opcode => 16#0021}, Out0, <<"ws-hi">>),
            assert_tcp_publish(TSock, <<"x/y">>, 0, 0, <<"ws-hi">>),
            %% TCP publishes QoS 1: WS receives it, TCP gets its PUBACK.
            ok = gen_tcp:send(TSock, publish_packet(<<"x/y">>, 42, 16#32, <<"tcp-hi">>)),
            TPub = wait_frame(Mock, TConn, 16#0020),
            {ok, TPubMeta} = indra_brokerlink:decode_publish_meta(maps:get(meta, TPub)),
            ?assertEqual(42, maps:get(packet_id, TPubMeta)),
            ok = indra_conn:broker_frame(
                   TConn, #{opcode => 16#0023},
                   indra_brokerlink:encode_puback_meta(42, 0), <<>>),
            ?assertEqual(<<16#40, 16#02, 16#00, 16#2A>>,
                         recv_exact(TSock, 4)),
            Out1 = indra_brokerlink:encode_publish_meta(<<"x/y">>, 77, 1, false, false),
            ok = indra_conn:broker_frame(
                   WConn, #{opcode => 16#0021}, Out1, <<"tcp-hi">>),
            assert_ws_publish(WSock, <<"x/y">>, 77, 1, <<"tcp-hi">>),
            %% WS publishes QoS 1: WS gets its PUBACK.
            ok = ws_client:send_binary(WSock, publish_packet(<<"x/y">>, 43, 16#32, <<"ws-again">>)),
            WPub1 = wait_frame(Mock, WConn, 16#0020, 2),
            {ok, WPub1Meta} = indra_brokerlink:decode_publish_meta(maps:get(meta, WPub1)),
            ?assertEqual(43, maps:get(packet_id, WPub1Meta)),
            ok = indra_conn:broker_frame(
                   WConn, #{opcode => 16#0023},
                   indra_brokerlink:encode_puback_meta(43, 0), <<>>),
            ?assertEqual(<<16#40, 16#02, 16#00, 16#2B>>, ws_client:recv_binary(WSock)),
            ok
        after
            gen_tcp:close(TSock),
            gen_tcp:close(WSock)
        end
    after
        indra_ws_listener:stop(Ws),
        indra_listener:stop(Tcp),
        mock_broker:stop(Mock)
    end.

%% @doc A bind rejection reaches a WS client with the same CONNACK code
%% as TCP (bad username/password -> 4).
ws_wrong_credentials_same_code_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Tcp} = indra_listener:start_link([{port, 0},
                                           {conn, [{broker, Mock}]}]),
    {ok, Ws} = indra_ws_listener:start_link([{port, 0},
                                             {conn, [{broker, Mock}]}]),
    try
        {ok, TcpPort} = indra_listener:get_port(Tcp),
        {ok, WsPort} = indra_ws_listener:get_port(Ws),
        {ok, TSock} = gen_tcp:connect("127.0.0.1", TcpPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        {ok, WSock} = gen_tcp:connect("127.0.0.1", WsPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        try
            ok = gen_tcp:send(TSock, connect_packet(<<"u">>, {<<"u">>, <<"bad">>},
                                                       true, 60)),
            ok = ws_client:handshake(WSock, "/mqtt"),
            ok = ws_client:send_binary(WSock, connect_packet(<<"u">>, {<<"u">>, <<"bad">>},
                                               true, 60)),
            [TBind, WBind] = wait_binds(Mock, <<"u">>, 2, 40),
            %% Kernel refuses both with MQTT 5 bad-username/password
            %% (16#86), which the edge folds to 3.1.1 code 4.
            Reject = indra_brokerlink:encode_session_binding_meta(9, false, 16#86),
            ok = indra_conn:broker_frame(maps:get(from, TBind),
                                         #{opcode => 16#0011}, Reject, <<>>),
            ok = indra_conn:broker_frame(maps:get(from, WBind),
                                         #{opcode => 16#0011}, Reject, <<>>),
            ?assertEqual(<<16#20, 16#02, 16#00, 16#04>>,
                         recv_exact(TSock, 4)),
            ?assertEqual(<<16#20, 16#02, 16#00, 16#04>>, ws_client:recv_binary(WSock))
        after
            gen_tcp:close(TSock),
            gen_tcp:close(WSock)
        end
    after
        indra_ws_listener:stop(Ws),
        indra_listener:stop(Tcp),
        mock_broker:stop(Mock)
    end.

%% @doc A protocol level TCP refuses, WS refuses too: only the levels
%% TCP serves are served over WS (today: 4 only).
ws_v5_refused_like_tcp_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Tcp} = indra_listener:start_link([{port, 0},
                                           {conn, [{broker, Mock}]}]),
    {ok, Ws} = indra_ws_listener:start_link([{port, 0},
                                             {conn, [{broker, Mock}]}]),
    try
        {ok, TcpPort} = indra_listener:get_port(Tcp),
        {ok, WsPort} = indra_ws_listener:get_port(Ws),
        {ok, TSock} = gen_tcp:connect("127.0.0.1", TcpPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        {ok, WSock} = gen_tcp:connect("127.0.0.1", WsPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        try
            ok = gen_tcp:send(TSock, connect_packet_v5(<<"t5">>)),
            ok = ws_client:handshake(WSock, "/mqtt"),
            ok = ws_client:send_binary(WSock, connect_packet_v5(<<"w5">>)),
            %% Neither bind reaches the broker; both peers are closed
            %% with no CONNACK.
            timer:sleep(300),
            ?assertEqual([], [F || F <- mock_broker:sent(Mock),
                                   maps:get(opcode, F) =:= 16#0010]),
            ?assertMatch({error, closed}, gen_tcp:recv(TSock, 0, ?RECV_TIMEOUT)),
            ?assertMatch({error, closed}, ws_client:wait_closed(WSock))
        after
            catch gen_tcp:close(TSock),
            catch gen_tcp:close(WSock)
        end
    after
        indra_ws_listener:stop(Ws),
        indra_listener:stop(Tcp),
        mock_broker:stop(Mock)
    end.

%% @doc Keepalive supervision is identical: an idle WS connection past
%% 1.5x keepalive is closed, answering a WS ping does not save it.
ws_keepalive_timeout_closes_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Ws} = indra_ws_listener:start_link([{port, 0},
                                             {conn, [{broker, Mock}]}]),
    try
        {ok, WsPort} = indra_ws_listener:get_port(Ws),
        {ok, WSock} = gen_tcp:connect("127.0.0.1", WsPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        try
            {_Conn, _} = ws_mqtt_handshake_keepalive(WSock, Mock, <<"ws-idle">>, 1),
            %% A transport ping is answered with a pong but buys no
            %% MQTT keepalive credit.
            ok = ws_client:send_frame(WSock, 16#9, <<"p">>),
            ?assertEqual({pong, <<"p">>}, ws_client:recv_event(WSock)),
            %% 1.5 s grace on keepalive 1: idle past it closes.
            ?assertMatch({error, closed}, ws_client:wait_closed(WSock, 5000))
        after
            catch gen_tcp:close(WSock)
        end
    after
        indra_ws_listener:stop(Ws),
        mock_broker:stop(Mock)
    end.

ws_ping_answered_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Ws} = indra_ws_listener:start_link([{port, 0},
                                             {conn, [{broker, Mock}]}]),
    try
        {ok, WsPort} = indra_ws_listener:get_port(Ws),
        {ok, WSock} = gen_tcp:connect("127.0.0.1", WsPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        try
            {_Conn, _} = ws_mqtt_handshake(WSock, Mock, <<"ws-ping">>),
            ok = ws_client:send_frame(WSock, 16#9, <<"hb">>),
            ?assertEqual({pong, <<"hb">>}, ws_client:recv_event(WSock))
        after
            gen_tcp:close(WSock)
        end
    after
        indra_ws_listener:stop(Ws),
        mock_broker:stop(Mock)
    end.

%%====================================================================
%% Helpers: MQTT packets + broker dance (mirrors indra_listener_tests)
%%
%% WS framing goes through the {@link ws_client} library; only MQTT
%% packet construction and the mock-broker dance stay local here.
%%====================================================================

%% @private WS CONNECT handshake with credentials; returns the conn pid.
ws_mqtt_handshake(Sock, Mock, ClientId) ->
    ws_mqtt_handshake_keepalive(Sock, Mock, ClientId, 60).

ws_mqtt_handshake_keepalive(Sock, Mock, ClientId, Keepalive) ->
    ok = ws_client:handshake(Sock, "/mqtt"),
    ok = ws_client:send_binary(Sock, connect_packet(ClientId, undefined, true, Keepalive)),
    Bind = wait_bind(Mock, ClientId, 40),
    Conn = maps:get(from, Bind),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = ws_client:recv_binary(Sock),
    {Conn, maps:get(conn_id, Bind)}.

tcp_handshake(Sock, Mock, ClientId) ->
    ok = gen_tcp:send(Sock, connect_packet(ClientId, undefined, true, 60)),
    Bind = wait_bind(Mock, ClientId, 40),
    Conn = maps:get(from, Bind),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = recv_exact(Sock, 4),
    {Conn, maps:get(conn_id, Bind)}.

wait_binds(_Mock, _Id, _N, 0) ->
    error(bind_frame_timeout);
wait_binds(Mock, Id, N, Tries) ->
    Binds = [F || F <- mock_broker:sent(Mock),
                  maps:get(opcode, F) =:= 16#0010,
                  bind_client(F) =:= Id],
    case length(Binds) >= N of
        true -> lists:sublist(Binds, N);
        false -> timer:sleep(50), wait_binds(Mock, Id, N, Tries - 1)
    end.

wait_frame(_Mock, _Pid, _Opcode, _N, 0) ->
    error(broker_frame_timeout);
wait_frame(Mock, Pid, Opcode, N, Tries) ->
    Found = [F || F <- mock_broker:sent(Mock),
                  maps:get(from, F) =:= Pid,
                  maps:get(opcode, F) =:= Opcode],
    case length(Found) >= N of
        true -> lists:nth(N, Found);
        false -> timer:sleep(50), wait_frame(Mock, Pid, Opcode, N, Tries - 1)
    end.

wait_frame(Mock, Pid, Opcode) ->
    wait_frame(Mock, Pid, Opcode, 1, 40).

wait_frame(Mock, Pid, Opcode, N) ->
    wait_frame(Mock, Pid, Opcode, N, 40).

wait_bind(_Mock, _ClientId, 0) ->
    error(bind_frame_timeout);
wait_bind(Mock, ClientId, Tries) ->
    Binds = [F || F <- mock_broker:sent(Mock),
                  maps:get(opcode, F) =:= 16#0010,
                  bind_client(F) =:= ClientId],
    case Binds of
        [Bind | _] -> Bind;
        [] -> timer:sleep(50), wait_bind(Mock, ClientId, Tries - 1)
    end.

bind_client(Frame) ->
    {ok, Meta} = indra_brokerlink:decode_bind_meta(maps:get(meta, Frame)),
    maps:get(client_id, Meta).

recv_exact(Sock, N) ->
    {ok, Bin} = gen_tcp:recv(Sock, N, ?RECV_TIMEOUT),
    Bin.

assert_tcp_publish(Client, Topic, PacketId, QoS, Payload) ->
    {ok, Bin} = gen_tcp:recv(Client, 0, ?RECV_TIMEOUT),
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                maps:get(flags, Pkt)),
    ?assertEqual(Topic, maps:get(topic, Pub)),
    ?assertEqual(PacketId, maps:get(packet_id, Pub)),
    ?assertEqual(QoS, maps:get(qos, Pub)),
    ?assertEqual(Payload, maps:get(payload, Pub)),
    ok.

assert_ws_publish(Sock, Topic, PacketId, QoS, Payload) ->
    {ok, Bin} = gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT),
    {ok, {binary, Mqtt}, _} = ws_client:parse_server_frame(Bin),
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Mqtt),
    {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                maps:get(flags, Pkt)),
    ?assertEqual(Topic, maps:get(topic, Pub)),
    ?assertEqual(PacketId, maps:get(packet_id, Pub)),
    ?assertEqual(QoS, maps:get(qos, Pub)),
    ?assertEqual(Payload, maps:get(payload, Pub)),
    ok.

connect_packet(ClientId, User, CleanStart, Keepalive) ->
    Flags0 = case CleanStart of true -> 16#02; false -> 16#00 end,
    {Flags, Tail} = case User of
        undefined -> {Flags0, <<>>};
        {U, undefined} ->
            {Flags0 bor 16#80,
             <<(byte_size(U)):16/big, U/binary>>};
        {U, P} ->
            {Flags0 bor 16#80 bor 16#40,
             <<(byte_size(U)):16/big, U/binary,
               (byte_size(P)):16/big, P/binary>>};
        U when is_binary(U) ->
            {Flags0 bor 16#80,
             <<(byte_size(U)):16/big, U/binary>>}
    end,
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary, Tail/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.

connect_packet_v5(ClientId) ->
    Var = <<0, 4, "MQTT", 5, 16#02:8, 60:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.

subscribe_packet(PacketId, Filters) ->
    Subs = lists:foldl(
        fun({Filter, QoS}, Acc) ->
            <<Acc/binary, (byte_size(Filter)):16/big, Filter/binary, QoS:8>>
        end, <<>>, Filters),
    Body = <<PacketId:16/big, Subs/binary>>,
    <<16#82, (byte_size(Body)), Body/binary>>.

publish_packet(Topic, PacketId, Flags, Payload) ->
    Var = case (Flags band 16#06) bsr 1 of
        0 -> <<(byte_size(Topic)):16/big, Topic/binary>>;
        _ -> <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big>>
    end,
    Body = <<Var/binary, Payload/binary>>,
    <<3:4, Flags:4, (byte_size(Body)), Body/binary>>.
