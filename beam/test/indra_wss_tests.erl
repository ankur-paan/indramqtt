%% @doc EUnit tests for MQTT over secure WebSocket (`wss').
%%
%% Self-terminating integration coverage: the WS listener binds an
%% ephemeral port with `{transport, ssl}', the test client completes a
%% real TLS handshake (test fixtures, never production material) and
%% then a real RFC 6455 upgrade (with `mqtt' subprotocol negotiation)
%% on the encrypted channel, and the resulting connection completes
%% the CONNECT -> CONNACK handshake against {@link mock_broker}
%% exactly like a TCP connection. Cross tests run a `wss' listener
%% and a TCP listener against the same mock broker and prove
%% deliveries flow both ways. Nothing outlives the test.
%%
%% Certificate posture mirrors the TCP/TLS listener: missing or
%% unreadable material fails the listener at startup (never a silent
%% plaintext fallback), no client-certificate authentication is
%% requested, and rotation needs a restart (neither listener reloads
%% material in place).
%%
%% The integration tests speak through the reusable {@link ws_client}
%% TLS library: the same fresh-key handshake, accept-key and
%% subprotocol verification as plaintext, over an `ssl' socket. A
%% browser or WS-capable MQTT client connects the same way.
-module(indra_wss_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).

%%====================================================================
%% Listener startup: fail closed without material
%%====================================================================

wss_missing_certfile_rejected_test() ->
    {_, Key} = test_certs(),
    process_flag(trap_exit, true),
    try
        ?assertMatch({error, _},
                     indra_ws_listener:start_link([{transport, ssl},
                                                  {port, 0},
                                                  {keyfile, Key}])),
        receive {'EXIT', _, _} -> ok after 1000 -> ok end
    after
        process_flag(trap_exit, false)
    end.

wss_missing_keyfile_rejected_test() ->
    {Cert, _} = test_certs(),
    process_flag(trap_exit, true),
    try
        ?assertMatch({error, _},
                     indra_ws_listener:start_link([{transport, ssl},
                                                  {port, 0},
                                                  {certfile, Cert}])),
        receive {'EXIT', _, _} -> ok after 1000 -> ok end
    after
        process_flag(trap_exit, false)
    end.

%%====================================================================
%% Handshake over TLS
%%====================================================================

wss_handshake_selects_mqtt_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_ws_listener:start_link([{transport, ssl},
                                                  {port, 0},
                                                  {certfile, Cert},
                                                  {keyfile, Key},
                                                  {conn, [{broker, Mock}]}]),
    try
        {ok, Port} = indra_ws_listener:get_port(Listener),
        {ok, Sock} = ssl:connect("127.0.0.1", Port,
                                 [binary, {packet, raw},
                                  {active, false}, {verify, verify_none}],
                                 5000),
        try
            ok = ws_client:handshake_tls(Sock, "/mqtt"),
            %% The listener answers 101 and selects mqtt; the mock
            %% broker has seen nothing yet (no MQTT bytes sent).
            ?assertEqual([], mock_broker:sent(Mock))
        after
            ssl:close(Sock)
        end
    after
        indra_ws_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc Plaintext WS bytes sent to the `wss' port are rejected: the
%% TLS handshake fails, the reason is logged, and the bytes are never
%% answered as MQTT.
wss_plaintext_bytes_rejected_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_ws_listener:start_link([{transport, ssl},
                                                  {port, 0},
                                                  {certfile, Cert},
                                                  {keyfile, Key},
                                                  {conn, [{broker, Mock}]}]),
    try
        {ok, Port} = indra_ws_listener:get_port(Listener),
        {ok, Sock} = gen_tcp:connect("127.0.0.1", Port,
                                     [binary, {packet, raw}, {active, false}],
                                     2000),
        try
            %% Plaintext HTTP upgrade bytes on a TLS port: not TLS.
            %% The server answers with a TLS fatal alert (record type
            %% 21) and closes; it never answers as MQTT.
            ok = gen_tcp:send(Sock, "GET /mqtt HTTP/1.1\r\nHost: x\r\n\r\n"),
            case gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT) of
                {error, _} ->
                    ok;
                {ok, <<21, 3, _/binary>>} ->
                    %% TLS alert record, then the close.
                    ?assertMatch({error, closed},
                                 gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT))
            end,
            %% Never answered as MQTT: no bind reached the broker.
            timer:sleep(200),
            ?assertEqual([], mock_broker:sent(Mock))
        after
            catch gen_tcp:close(Sock)
        end
    after
        indra_ws_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc A `wss' connection whose chain the client does not trust fails
%% closed: the client's TLS handshake refuses the server certificate.
wss_untrusted_chain_fails_closed_test() ->
    {Cert, Key} = test_certs(),
    {Untrusted, _} = untrusted_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_ws_listener:start_link([{transport, ssl},
                                                  {port, 0},
                                                  {certfile, Cert},
                                                  {keyfile, Key},
                                                  {conn, [{broker, Mock}]}]),
    try
        {ok, Port} = indra_ws_listener:get_port(Listener),
        ?assertMatch({error, _},
                     ssl:connect("127.0.0.1", Port,
                                [binary, {packet, raw},
                                 {active, false},
                                 {verify, verify_peer},
                                 {cacertfile, Untrusted},
                                 {server_name_indication, "localhost"},
                                 {customize_hostname_check,
                                  [{match_fun,
                                    public_key:pkix_verify_hostname_match_fun(https)}]}],
                                5000)),
        %% No bind reached the broker.
        timer:sleep(200),
        ?assertEqual([], mock_broker:sent(Mock))
    after
        indra_ws_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc A certificate for the wrong host is refused when the client
%% verifies the hostname.
wss_wrong_host_refused_test() ->
    {WrongCert, WrongKey} = wronghost_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_ws_listener:start_link([{transport, ssl},
                                                  {port, 0},
                                                  {certfile, WrongCert},
                                                  {keyfile, WrongKey},
                                                  {conn, [{broker, Mock}]}]),
    try
        {ok, Port} = indra_ws_listener:get_port(Listener),
        ?assertMatch({error, _},
                     ssl:connect("127.0.0.1", Port,
                                [binary, {packet, raw},
                                 {active, false},
                                 {verify, verify_peer},
                                 {cacertfile, WrongCert},
                                 {server_name_indication, "localhost"},
                                 {customize_hostname_check,
                                  [{match_fun,
                                    public_key:pkix_verify_hostname_match_fun(https)}]}],
                                5000)),
        timer:sleep(200),
        ?assertEqual([], mock_broker:sent(Mock))
    after
        indra_ws_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc An expired certificate is refused when the client verifies
%% the chain.
wss_expired_refused_test() ->
    {ExpCert, ExpKey, ExpCa} = expired_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_ws_listener:start_link([{transport, ssl},
                                                  {port, 0},
                                                  {certfile, ExpCert},
                                                  {keyfile, ExpKey},
                                                  {conn, [{broker, Mock}]}]),
    try
        {ok, Port} = indra_ws_listener:get_port(Listener),
        ?assertMatch({error, _},
                     ssl:connect("127.0.0.1", Port,
                                [binary, {packet, raw},
                                 {active, false},
                                 {verify, verify_peer},
                                 {cacertfile, ExpCa},
                                 {server_name_indication, "localhost"},
                                 {customize_hostname_check,
                                  [{match_fun,
                                    public_key:pkix_verify_hostname_match_fun(https)}]}],
                                5000)),
        timer:sleep(200),
        ?assertEqual([], mock_broker:sent(Mock))
    after
        indra_ws_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%%====================================================================
%% MQTT over the encrypted channel
%%====================================================================

%% @doc WSS connect carries the same bind metadata as TCP: the kernel
%% enforces wrong-password, quota and ban decisions on identical input,
%% so per-user quotas apply equally to all transports.
wss_bind_matches_tcp_bind_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Tcp} = indra_listener:start_link([{port, 0},
                                           {conn, [{broker, Mock}]}]),
    {ok, Wss} = indra_ws_listener:start_link([{transport, ssl},
                                              {port, 0},
                                              {certfile, Cert},
                                              {keyfile, Key},
                                              {conn, [{broker, Mock}]}]),
    try
        {ok, TcpPort} = indra_listener:get_port(Tcp),
        {ok, WssPort} = indra_ws_listener:get_port(Wss),
        {ok, TSock} = gen_tcp:connect("127.0.0.1", TcpPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        {ok, WSock} = ssl:connect("127.0.0.1", WssPort,
                                  [binary, {packet, raw},
                                   {active, false}, {verify, verify_none}],
                                  5000),
        try
            Connect = connect_packet(<<"quota-user">>, {<<"quota-user">>, <<"pw9">>},
                                       true, 60),
            ok = gen_tcp:send(TSock, Connect),
            ok = ws_client:handshake_tls(WSock, "/mqtt"),
            ok = ws_client:send_binary_tls(WSock, Connect),
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
            ssl:close(WSock)
        end
    after
        indra_ws_listener:stop(Wss),
        indra_listener:stop(Tcp),
        mock_broker:stop(Mock)
    end.

%% @doc A WSS publish reaches a TCP subscriber and a TCP publish reaches
%% a WSS subscriber (QoS 0 and QoS 1), through the real listeners and
%% the broker path.
wss_tcp_cross_delivery_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Tcp} = indra_listener:start_link([{port, 0},
                                           {conn, [{broker, Mock}]}]),
    {ok, Wss} = indra_ws_listener:start_link([{transport, ssl},
                                              {port, 0},
                                              {certfile, Cert},
                                              {keyfile, Key},
                                              {conn, [{broker, Mock}]}]),
    try
        {ok, TcpPort} = indra_listener:get_port(Tcp),
        {ok, WssPort} = indra_ws_listener:get_port(Wss),
        {ok, TSock} = gen_tcp:connect("127.0.0.1", TcpPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        {ok, WSock} = ssl:connect("127.0.0.1", WssPort,
                                  [binary, {packet, raw},
                                   {active, false}, {verify, verify_none}],
                                  5000),
        try
            {TConn, _} = tcp_handshake(TSock, Mock, <<"tcp-sub">>),
            {WConn, _} = wss_mqtt_handshake(WSock, Mock, <<"wss-sub">>),
            %% Both subscribe to the same topic.
            ok = gen_tcp:send(TSock, subscribe_packet(7, [{<<"x/y">>, 1}])),
            TSub = wait_frame(Mock, TConn, 16#0030),
            {ok, TSubMeta} = indra_brokerlink:decode_subscribe_meta(maps:get(meta, TSub)),
            ?assertEqual(7, maps:get(packet_id, TSubMeta)),
            ok = ws_client:send_binary_tls(WSock, subscribe_packet(9, [{<<"x/y">>, 1}])),
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
                         ws_client:recv_binary_tls(WSock)),
            %% WSS publishes QoS 0: TCP receives it.
            ok = ws_client:send_binary_tls(WSock, publish_packet(<<"x/y">>, 0, 16#30, <<"wss-hi">>)),
            WPub = wait_frame(Mock, WConn, 16#0020),
            {ok, WPubMeta} = indra_brokerlink:decode_publish_meta(maps:get(meta, WPub)),
            ?assertEqual(<<"x/y">>, maps:get(topic, WPubMeta)),
            Out0 = indra_brokerlink:encode_publish_meta(<<"x/y">>, 0, 0, false, false),
            ok = indra_conn:broker_frame(
                   TConn, #{opcode => 16#0021}, Out0, <<"wss-hi">>),
            assert_tcp_publish(TSock, <<"x/y">>, 0, 0, <<"wss-hi">>),
            %% TCP publishes QoS 1: WSS receives it, TCP gets its PUBACK.
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
            assert_wss_publish(WSock, <<"x/y">>, 77, 1, <<"tcp-hi">>),
            %% WSS publishes QoS 1: WSS gets its PUBACK.
            ok = ws_client:send_binary_tls(WSock, publish_packet(<<"x/y">>, 43, 16#32, <<"wss-again">>)),
            WPub1 = wait_frame(Mock, WConn, 16#0020, 2),
            {ok, WPub1Meta} = indra_brokerlink:decode_publish_meta(maps:get(meta, WPub1)),
            ?assertEqual(43, maps:get(packet_id, WPub1Meta)),
            ok = indra_conn:broker_frame(
                   WConn, #{opcode => 16#0023},
                   indra_brokerlink:encode_puback_meta(43, 0), <<>>),
            ?assertEqual(<<16#40, 16#02, 16#00, 16#2B>>, ws_client:recv_binary_tls(WSock)),
            ok
        after
            gen_tcp:close(TSock),
            ssl:close(WSock)
        end
    after
        indra_ws_listener:stop(Wss),
        indra_listener:stop(Tcp),
        mock_broker:stop(Mock)
    end.

%% @doc A bind rejection reaches a WSS client with the same CONNACK code
%% as TCP (bad username/password -> 4).
wss_wrong_credentials_same_code_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Tcp} = indra_listener:start_link([{port, 0},
                                           {conn, [{broker, Mock}]}]),
    {ok, Wss} = indra_ws_listener:start_link([{transport, ssl},
                                              {port, 0},
                                              {certfile, Cert},
                                              {keyfile, Key},
                                              {conn, [{broker, Mock}]}]),
    try
        {ok, TcpPort} = indra_listener:get_port(Tcp),
        {ok, WssPort} = indra_ws_listener:get_port(Wss),
        {ok, TSock} = gen_tcp:connect("127.0.0.1", TcpPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        {ok, WSock} = ssl:connect("127.0.0.1", WssPort,
                                  [binary, {packet, raw},
                                   {active, false}, {verify, verify_none}],
                                  5000),
        try
            ok = gen_tcp:send(TSock, connect_packet(<<"u">>, {<<"u">>, <<"bad">>},
                                                       true, 60)),
            ok = ws_client:handshake_tls(WSock, "/mqtt"),
            ok = ws_client:send_binary_tls(WSock, connect_packet(<<"u">>, {<<"u">>, <<"bad">>},
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
            ?assertEqual(<<16#20, 16#02, 16#00, 16#04>>, ws_client:recv_binary_tls(WSock))
        after
            gen_tcp:close(TSock),
            ssl:close(WSock)
        end
    after
        indra_ws_listener:stop(Wss),
        indra_listener:stop(Tcp),
        mock_broker:stop(Mock)
    end.

%% @doc A protocol level TCP refuses, WSS refuses too: only the levels
%% TCP serves are served over WSS (today: 4 only).
wss_v5_refused_like_tcp_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Tcp} = indra_listener:start_link([{port, 0},
                                           {conn, [{broker, Mock}]}]),
    {ok, Wss} = indra_ws_listener:start_link([{transport, ssl},
                                              {port, 0},
                                              {certfile, Cert},
                                              {keyfile, Key},
                                              {conn, [{broker, Mock}]}]),
    try
        {ok, TcpPort} = indra_listener:get_port(Tcp),
        {ok, WssPort} = indra_ws_listener:get_port(Wss),
        {ok, TSock} = gen_tcp:connect("127.0.0.1", TcpPort,
                                      [binary, {packet, raw}, {active, false}],
                                      2000),
        {ok, WSock} = ssl:connect("127.0.0.1", WssPort,
                                  [binary, {packet, raw},
                                   {active, false}, {verify, verify_none}],
                                  5000),
        try
            ok = gen_tcp:send(TSock, connect_packet_v5(<<"t5">>)),
            ok = ws_client:handshake_tls(WSock, "/mqtt"),
            ok = ws_client:send_binary_tls(WSock, connect_packet_v5(<<"w5">>)),
            %% Neither bind reaches the broker; both peers are closed
            %% with no CONNACK.
            timer:sleep(300),
            ?assertEqual([], [F || F <- mock_broker:sent(Mock),
                                   maps:get(opcode, F) =:= 16#0010]),
            ?assertMatch({error, closed}, gen_tcp:recv(TSock, 0, ?RECV_TIMEOUT)),
            ?assertMatch({error, closed}, ws_client:wait_closed_tls(WSock))
        after
            catch gen_tcp:close(TSock),
            catch ssl:close(WSock)
        end
    after
        indra_ws_listener:stop(Wss),
        indra_listener:stop(Tcp),
        mock_broker:stop(Mock)
    end.

%% @doc Keepalive supervision is identical: an idle WSS connection past
%% 1.5x keepalive is closed, answering a WS ping does not save it.
wss_keepalive_timeout_closes_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Wss} = indra_ws_listener:start_link([{transport, ssl},
                                              {port, 0},
                                              {certfile, Cert},
                                              {keyfile, Key},
                                              {conn, [{broker, Mock}]}]),
    try
        {ok, WssPort} = indra_ws_listener:get_port(Wss),
        {ok, WSock} = ssl:connect("127.0.0.1", WssPort,
                                  [binary, {packet, raw},
                                   {active, false}, {verify, verify_none}],
                                  5000),
        try
            {_Conn, _} = wss_mqtt_handshake_keepalive(WSock, Mock, <<"wss-idle">>, 1),
            %% A transport ping is answered with a pong but buys no
            %% MQTT keepalive credit.
            ok = ws_client:send_frame_tls(WSock, 16#9, <<"p">>),
            ?assertEqual({pong, <<"p">>}, ws_client:recv_event_tls(WSock)),
            %% 1.5 s grace on keepalive 1: idle past it closes.
            ?assertMatch({error, closed}, ws_client:wait_closed_tls(WSock, 5000))
        after
            catch ssl:close(WSock)
        end
    after
        indra_ws_listener:stop(Wss),
        mock_broker:stop(Mock)
    end.

wss_ping_answered_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Wss} = indra_ws_listener:start_link([{transport, ssl},
                                              {port, 0},
                                              {certfile, Cert},
                                              {keyfile, Key},
                                              {conn, [{broker, Mock}]}]),
    try
        {ok, WssPort} = indra_ws_listener:get_port(Wss),
        {ok, WSock} = ssl:connect("127.0.0.1", WssPort,
                                  [binary, {packet, raw},
                                   {active, false}, {verify, verify_none}],
                                  5000),
        try
            {_Conn, _} = wss_mqtt_handshake(WSock, Mock, <<"wss-ping">>),
            ok = ws_client:send_frame_tls(WSock, 16#9, <<"hb">>),
            ?assertEqual({pong, <<"hb">>}, ws_client:recv_event_tls(WSock))
        after
            ssl:close(WSock)
        end
    after
        indra_ws_listener:stop(Wss),
        mock_broker:stop(Mock)
    end.

%%====================================================================
%% Helpers: MQTT packets + broker dance (mirrors indra_ws_tests)
%%
%% WS framing goes through the {@link ws_client} TLS library; only MQTT
%% packet construction and the mock-broker dance stay local here.
%%====================================================================

%% @private WSS CONNECT handshake with credentials; returns the conn pid.
wss_mqtt_handshake(Sock, Mock, ClientId) ->
    wss_mqtt_handshake_keepalive(Sock, Mock, ClientId, 60).

wss_mqtt_handshake_keepalive(Sock, Mock, ClientId, Keepalive) ->
    ok = ws_client:handshake_tls(Sock, "/mqtt"),
    ok = ws_client:send_binary_tls(Sock, connect_packet(ClientId, undefined, true, Keepalive)),
    Bind = wait_bind(Mock, ClientId, 40),
    Conn = maps:get(from, Bind),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = ws_client:recv_binary_tls(Sock),
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

assert_wss_publish(Sock, Topic, PacketId, QoS, Payload) ->
    {ok, Bin} = ssl:recv(Sock, 0, ?RECV_TIMEOUT),
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

%% @private Locate the committed self-signed fixtures. Works whether the
%% suite runs from `beam/' or the repo root.
test_certs() ->
    {find_cert("cert.pem"), find_cert("key.pem")}.

%% @private An unrelated self-signed certificate the client trusts
%% instead of the server's: the handshake must fail closed.
untrusted_certs() ->
    {find_cert("untrusted-cert.pem"), find_cert("untrusted-key.pem")}.

%% @private A certificate for `wronghost.invalid': hostname
%% verification against `localhost' must refuse it.
wronghost_certs() ->
    {find_cert("wronghost-cert.pem"), find_cert("wronghost-key.pem")}.

%% @private An expired `localhost' certificate plus the CA that signed
%% it: chain verification must refuse it for expiry.
expired_certs() ->
    {find_cert("expired-cert.pem"), find_cert("expired-key.pem"),
     find_cert("expired-ca.pem")}.

find_cert(Name) ->
    Candidates = ["test/certs/" ++ Name, "beam/test/certs/" ++ Name],
    case lists:dropwhile(fun(C) -> filelib:is_regular(C) =:= false end,
                         Candidates) of
        [Found | _] -> Found;
        [] -> error({missing_test_certs, Candidates})
    end.
