%% @doc EUnit tests for {@link indra_conn} (CONNECT -> CONNACK handshake).
%%
%% All tests are self-terminating: every socket is closed and every
%% process stopped within the test. No daemons, no external services —
%% the Rust core is replaced by {@link mock_broker}.
-module(indra_conn_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).

%%====================================================================
%% Happy paths
%%====================================================================

connect_clean_start_handshake_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5001}]),
    _ = Port,
    try
        ok = gen_tcp:send(Client, connect_packet(<<"dev-1">>, true, 60)),
        %% Edge must emit exactly one BindConnection frame.
        [Sent] = wait_frames(Mock, 1),
        ?assertEqual(16#0010, maps:get(opcode, Sent)),
        ?assertEqual(5001, maps:get(conn_id, Sent)),
        ?assertEqual(1, maps:get(seq_no, Sent)),
        ?assertEqual(<<>>, maps:get(payload, Sent)),
        {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Sent)),
        ?assertEqual(<<"dev-1">>, maps:get(client_id, Bind)),
        ?assertEqual(true, maps:get(clean_start, Bind)),
        ?assertEqual(60, maps:get(keepalive, Bind)),
        %% Rust answers SessionBinding (fresh session, RC 0).
        Binding = indra_brokerlink:encode_session_binding_meta(12345, false, 0),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
        %% Client receives CONNACK with session_present = 0.
        ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>,
                     recv_exact(Client, 4)),
        %% State machine reached `connected`.
        ?assertMatch({connected, _}, sys:get_state(Conn))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

connect_resumed_session_sets_present_flag_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5002}]),
    _ = Port,
    try
        ok = gen_tcp:send(Client, connect_packet(<<"dev-2">>, false, 30)),
        [Sent] = wait_frames(Mock, 1),
        {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Sent)),
        ?assertEqual(<<"dev-2">>, maps:get(client_id, Bind)),
        ?assertEqual(false, maps:get(clean_start, Bind)),
        ?assertEqual(30, maps:get(keepalive, Bind)),
        Binding = indra_brokerlink:encode_session_binding_meta(777, true, 0),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
        %% CONNACK with session_present = 1.
        ?assertEqual(<<16#20, 16#02, 16#01, 16#00>>,
                     recv_exact(Client, 4)),
        ?assertMatch({connected, _}, sys:get_state(Conn))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

connect_fragmented_tcp_reassembly_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5003}]),
    _ = Port,
    try
        Full = connect_packet(<<"frag">>, true, 60),
        %% Split mid-variable-header: edge must buffer and still handshake.
        Half = byte_size(Full) div 2,
        <<A:Half/binary, B/binary>> = Full,
        ok = gen_tcp:send(Client, A),
        timer:sleep(100),
        ?assertEqual([], mock_broker:sent(Mock)),
        ok = gen_tcp:send(Client, B),
        [Sent] = wait_frames(Mock, 1),
        {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Sent)),
        ?assertEqual(<<"frag">>, maps:get(client_id, Bind)),
        Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
        ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>,
                     recv_exact(Client, 4)),
        ?assertMatch({connected, _}, sys:get_state(Conn))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

%%====================================================================
%% Rejection paths
%%====================================================================

non_connect_first_packet_closes_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5004}]),
    _ = Port,
    Ref = monitor(process, Conn),
    try
        %% PINGREQ as the first packet violates MQTT 3.1.1 §3.1.
        ok = gen_tcp:send(Client, <<16#C0, 16#00>>),
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT)),
        ?assertEqual([], mock_broker:sent(Mock)),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(conn_did_not_stop)
        end
    after
        teardown(LSock, Mock, Client, Conn),
        demonitor(Ref, [flush])
    end.

malformed_connect_closes_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5005}]),
    _ = Port,
    Ref = monitor(process, Conn),
    try
        %% CONNECT with the reserved flag bit set is malformed.
        Bad = connect_packet_raw(<<"dev-x">>, 16#03, 60),
        ok = gen_tcp:send(Client, Bad),
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT)),
        ?assertEqual([], mock_broker:sent(Mock)),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(conn_did_not_stop)
        end
    after
        teardown(LSock, Mock, Client, Conn),
        demonitor(Ref, [flush])
    end.

rejected_session_binding_closes_after_connack_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5006}]),
    _ = Port,
    Ref = monitor(process, Conn),
    try
        ok = gen_tcp:send(Client, connect_packet(<<"dev-6">>, true, 60)),
        [_Sent] = wait_frames(Mock, 1),
        %% Rust rejects (e.g. identifier rejected): CONNACK RC 4, then close.
        Binding = indra_brokerlink:encode_session_binding_meta(0, false, 4),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
        ?assertEqual(<<16#20, 16#02, 16#00, 16#04>>,
                     recv_exact(Client, 4)),
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT)),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(conn_did_not_stop)
        end
    after
        teardown(LSock, Mock, Client, Conn),
        demonitor(Ref, [flush])
    end.

connect_timeout_closes_idle_peer_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5007},
                                               {connect_timeout_ms, 100}]),
    _ = Port,
    Ref = monitor(process, Conn),
    try
        %% Send nothing: the first-packet deadline must fire.
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(connect_timeout_did_not_fire)
        end,
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT))
    after
        teardown(LSock, Mock, Client, Conn),
        demonitor(Ref, [flush])
    end.

keepalive_timeout_closes_idle_peer_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5008}]),
    _ = Port,
    Ref = monitor(process, Conn),
    try
        %% keepalive = 1s, so the 1.5s idle timer fires quickly.
        ok = gen_tcp:send(Client, connect_packet(<<"dev-8">>, true, 1)),
        [_Sent] = wait_frames(Mock, 1),
        Binding = indra_brokerlink:encode_session_binding_meta(9, false, 0),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
        ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>,
                     recv_exact(Client, 4)),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after 4000 -> error(keepalive_timeout_did_not_fire)
        end,
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT))
    after
        teardown(LSock, Mock, Client, Conn),
        demonitor(Ref, [flush])
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% @private Listen on loopback, accept one socket into an indra_conn,
%% and connect a test client. Returns {LSock, Port, Mock, Client, Conn}.
setup(ConnOpts) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    {ok, Mock} = mock_broker:start_link(),
    Parent = self(),
    spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Conn} = indra_conn:start_link(Sock, [{broker, Mock} | ConnOpts]),
        ok = gen_tcp:controlling_process(Sock, Conn),
        gen_statem:cast(Conn, takeover),
        Parent ! {conn_ready, Conn}
    end),
    {ok, Client} = gen_tcp:connect("127.0.0.1", Port,
                                   [binary, {packet, raw}, {active, false}],
                                   5000),
    Conn = receive {conn_ready, C} -> C
           after 5000 -> error(conn_not_ready)
           end,
    {LSock, Port, Mock, Client, Conn}.

teardown(LSock, Mock, Client, Conn) ->
    catch indra_conn:stop(Conn),
    catch gen_tcp:close(Client),
    catch gen_tcp:close(LSock),
    catch mock_broker:stop(Mock),
    ok.

wait_frames(Mock, N) ->
    wait_frames(Mock, N, 40).

wait_frames(_Mock, _N, 0) ->
    error(broker_frame_timeout);
wait_frames(Mock, N, Tries) ->
    case mock_broker:sent(Mock) of
        Frames when length(Frames) >= N -> Frames;
        _ -> timer:sleep(50), wait_frames(Mock, N, Tries - 1)
    end.

recv_exact(Sock, N) ->
    {ok, Bin} = gen_tcp:recv(Sock, N, ?RECV_TIMEOUT),
    Bin.

%% @private Minimal MQTT 3.1.1 CONNECT (remaining length < 128 bytes).
connect_packet(ClientId, CleanStart, Keepalive) ->
    Flags = case CleanStart of true -> 16#02; false -> 16#00 end,
    connect_packet_raw(ClientId, Flags, Keepalive).

connect_packet_raw(ClientId, Flags, Keepalive) ->
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.
