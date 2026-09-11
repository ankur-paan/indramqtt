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
    try        ok = gen_tcp:send(Client, connect_packet(<<"dev-1">>, true, 60)),
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

connect_forwards_credentials_in_bind_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5009}]),
    _ = Port,
    try
        ok = gen_tcp:send(Client, connect_packet_creds(<<"dev-auth">>, <<"alice">>, <<"s3cret">>)),
        [Sent] = wait_frames(Mock, 1),
        ?assertEqual(16#0010, maps:get(opcode, Sent)),
        {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Sent)),
        ?assertEqual(<<"dev-auth">>, maps:get(client_id, Bind)),
        ?assertEqual(<<"alice">>, maps:get(username, Bind)),
        ?assertEqual(<<"s3cret">>, maps:get(password, Bind)),
        %% Auth rejection (RC 0x86) still yields CONNACK-then-close.
        Binding = indra_brokerlink:encode_session_binding_meta(0, false, 16#86),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
        ?assertEqual(<<16#20, 16#02, 16#00, 16#86>>,
                     recv_exact(Client, 4)),
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

connect_resumed_session_sets_present_flag_test() ->    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 5002}]),
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
%% Sprint 3 messaging loop
%%====================================================================

subscribe_suback_flow_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6001}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-s">>, Conn),
        ok = gen_tcp:send(Client, subscribe_packet(7, [{<<"sport/tennis">>, 1}])),
        [_Bind, Sub] = wait_frames(Mock, 2),
        ?assertEqual(16#0030, maps:get(opcode, Sub)),
        ?assertEqual(6001, maps:get(conn_id, Sub)),
        ?assertEqual(2, maps:get(seq_no, Sub)),
        {ok, SubMeta} = indra_brokerlink:decode_subscribe_meta(maps:get(meta, Sub)),
        ?assertEqual(7, maps:get(packet_id, SubMeta)),
        ?assertEqual(<<"dev-s">>, maps:get(client_id, SubMeta)),
        ?assertEqual([{<<"sport/tennis">>, 1}], maps:get(subscriptions, SubMeta)),
        %% Rust answers SubAckOut granting QoS 1.
        AckMeta = indra_brokerlink:encode_suback_meta(7, [1]),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0031}, AckMeta, <<>>),
        ?assertEqual(<<16#90, 16#03, 16#00, 16#07, 16#01>>,
                     recv_exact(Client, 5)),
        {connected, Data} = sys:get_state(Conn),
        ?assertEqual(#{}, maps:get(subs_pending, Data))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

publish_qos0_flow_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6002}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-p0">>, Conn),
        ok = gen_tcp:send(Client, publish_packet(<<"t">>, 0, 16#30, <<"hi">>)),
        [_Bind, Pub] = wait_frames(Mock, 2),
        ?assertEqual(16#0020, maps:get(opcode, Pub)),
        ?assertEqual(<<"hi">>, maps:get(payload, Pub)),
        {ok, PubMeta} = indra_brokerlink:decode_publish_meta(maps:get(meta, Pub)),
        ?assertEqual(<<"t">>, maps:get(topic, PubMeta)),
        ?assertEqual(0, maps:get(packet_id, PubMeta)),
        ?assertEqual(0, maps:get(qos, PubMeta)),
        %% QoS 0 needs no reply from the edge.
        ?assertEqual({error, timeout}, gen_tcp:recv(Client, 0, 200)),
        ?assertMatch({connected, _}, sys:get_state(Conn))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

publish_qos1_puback_flow_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6003}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-p1">>, Conn),
        ok = gen_tcp:send(Client, publish_packet(<<"a/b">>, 42, 16#32, <<"data">>)),
        [_Bind, Pub] = wait_frames(Mock, 2),
        {ok, PubMeta} = indra_brokerlink:decode_publish_meta(maps:get(meta, Pub)),
        ?assertEqual(42, maps:get(packet_id, PubMeta)),
        ?assertEqual(1, maps:get(qos, PubMeta)),
        %% Rust answers PubAckOut; the edge emits PUBACK.
        AckMeta = indra_brokerlink:encode_puback_meta(42, 0),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0023}, AckMeta, <<>>),
        ?assertEqual(<<16#40, 16#02, 16#00, 16#2A>>,
                     recv_exact(Client, 4)),
        {connected, Data} = sys:get_state(Conn),
        ?assertEqual(#{}, maps:get(pubs_pending, Data))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

inbound_publishout_to_socket_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6004}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-r">>, Conn),
        %% Rust routes a downstream delivery at QoS 1.
        Meta = indra_brokerlink:encode_publish_meta(<<"sport/tennis">>, 99, 1, false, false),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0021}, Meta, <<"live">>),
        {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(recv_all(Client)),
        ?assertEqual(publish, maps:get(type_atom, Pkt)),
        {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                    maps:get(flags, Pkt)),
        ?assertEqual(<<"sport/tennis">>, maps:get(topic, Pub)),
        ?assertEqual(99, maps:get(packet_id, Pub)),
        ?assertEqual(1, maps:get(qos, Pub)),
        ?assertEqual(<<"live">>, maps:get(payload, Pub))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

inbound_retained_publishout_sets_retain_bit_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6009}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-ret">>, Conn),
        %% Retained replay must reach the socket with the RETAIN bit set.
        Meta = indra_brokerlink:encode_publish_meta(<<"device/state">>, 0, 0, true, false),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0021}, Meta, <<"online">>),
        {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(recv_all(Client)),
        {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                    maps:get(flags, Pkt)),
        ?assertEqual(<<"device/state">>, maps:get(topic, Pub)),
        ?assertEqual(true, maps:get(retain, Pub)),
        ?assertEqual(<<"online">>, maps:get(payload, Pub))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

pingreq_pingresp_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6005}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-ping">>, Conn),
        ok = gen_tcp:send(Client, <<16#C0, 16#00>>),
        %% Fast edge reply, no broker round-trip involved.
        ?assertEqual(<<16#D0, 16#00>>, recv_exact(Client, 2)),
        ?assertEqual(1, length(mock_broker:sent(Mock))),
        ?assertMatch({connected, _}, sys:get_state(Conn))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

disconnect_unbinds_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6006}]),
    _ = Port,
    Ref = monitor(process, Conn),
    try
        handshake(Client, Mock, <<"dev-d">>, Conn),
        ok = gen_tcp:send(Client, <<16#E0, 16#00>>),
        [_Bind, Unbind] = wait_frames(Mock, 2),
        ?assertEqual(16#0012, maps:get(opcode, Unbind)),
        {ok, UnMeta} = indra_brokerlink:decode_unbind_meta(maps:get(meta, Unbind)),
        ?assertEqual(<<"dev-d">>, maps:get(client_id, UnMeta)),
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT)),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(conn_did_not_stop)
        end
    after
        teardown(LSock, Mock, Client, Conn),
        demonitor(Ref, [flush])
    end.

second_connect_closes_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6007}]),
    _ = Port,
    Ref = monitor(process, Conn),
    try
        handshake(Client, Mock, <<"dev-c2">>, Conn),
        ok = gen_tcp:send(Client, connect_packet(<<"dev-c2">>, true, 60)),
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT)),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(conn_did_not_stop)
        end
    after
        teardown(LSock, Mock, Client, Conn),
        demonitor(Ref, [flush])
    end.

pipelined_connect_subscribe_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6008}]),
    _ = Port,
    try
        %% CONNECT and SUBSCRIBE in one TCP segment: SUBSCRIBE must wait
        %% for the handshake, then flow once connected.
        Both = <<(connect_packet(<<"dev-pipe">>, true, 60))/binary,
                 (subscribe_packet(3, [{<<"t">>, 0}]))/binary>>,
        ok = gen_tcp:send(Client, Both),
        [_Bind] = wait_frames(Mock, 1),
        %% Complete the handshake first: CONNACK arrives before SUBACK.
        Binding = indra_brokerlink:encode_session_binding_meta(5, false, 0),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
        ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>,
                     recv_exact(Client, 4)),
        %% The stashed SUBSCRIBE drains now that the conn is connected.
        [_BindAgain, Sub] = wait_frames(Mock, 2),
        ?assertEqual(16#0030, maps:get(opcode, Sub)),
        AckMeta = indra_brokerlink:encode_suback_meta(3, [0]),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0031}, AckMeta, <<>>),
        ?assertEqual(<<16#90, 16#03, 16#00, 16#03, 16#00>>,
                     recv_exact(Client, 5))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

%%====================================================================
%% Sprint 11 core holding + rebind
%%====================================================================

broker_down_moves_to_await_core_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6201}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-hold">>, Conn),
        ?assertMatch({connected, _}, sys:get_state(Conn)),
        gen_statem:cast(Conn, {broker_down}),
        ?assertMatch({await_core, _}, wait_state(Conn, await_core)),
        %% Socket stays open: no EOF, and the process is alive.
        ?assertEqual({error, timeout}, gen_tcp:recv(Client, 0, 200)),
        ?assert(is_process_alive(Conn))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

broker_up_rebinds_session_non_clean_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6202}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-rebind">>, Conn),
        gen_statem:cast(Conn, {broker_down}),
        ?assertMatch({await_core, _}, wait_state(Conn, await_core)),
        %% Replacement core announces itself (same mock pid here).
        gen_statem:cast(Conn, {broker_up, Mock}),
        %% Rebind observed: same client, forced non-clean, next seq.
        [_, Rebind] = wait_frames(Mock, 2),
        ?assertEqual(16#0010, maps:get(opcode, Rebind)),
        {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Rebind)),
        ?assertEqual(<<"dev-rebind">>, maps:get(client_id, Bind)),
        ?assertEqual(false, maps:get(clean_start, Bind)),
        %% Core kept state: straight back to connected, no CONNACK repeat.
        Binding = indra_brokerlink:encode_session_binding_meta(99, true, 0),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
        ?assertMatch({connected, _}, wait_state(Conn, connected)),
        ?assertEqual({error, timeout}, gen_tcp:recv(Client, 0, 200))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

rebind_without_state_resubscribes_silently_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6203}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-resub">>, Conn),
        %% One live subscription, fully acked.
        ok = gen_tcp:send(Client, subscribe_packet(7, [{<<"sport/tennis">>, 1}])),
        [_Bind, _Sub] = wait_frames(Mock, 2),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0031},
                                     indra_brokerlink:encode_suback_meta(7, [1]), <<>>),
        ?assertEqual(<<16#90, 16#03, 16#00, 16#07, 16#01>>,
                     recv_exact(Client, 5)),
        %% Core flaps and loses state.
        gen_statem:cast(Conn, {broker_down}),
        ?assertMatch({await_core, _}, wait_state(Conn, await_core)),
        gen_statem:cast(Conn, {broker_up, Mock}),
        [_B1, _S1, Rebind] = wait_frames(Mock, 3),
        ?assertEqual(16#0010, maps:get(opcode, Rebind)),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011},
                                     indra_brokerlink:encode_session_binding_meta(100, false, 0),
                                     <<>>),
        %% Re-registration goes out with the original packet id...
        [_B2, _S2, _RB, Resub] = wait_frames(Mock, 4),
        ?assertEqual(16#0030, maps:get(opcode, Resub)),
        {ok, ResubMeta} = indra_brokerlink:decode_subscribe_meta(maps:get(meta, Resub)),
        ?assertEqual(7, maps:get(packet_id, ResubMeta)),
        ?assertEqual([{<<"sport/tennis">>, 1}], maps:get(subscriptions, ResubMeta)),
        %% ...but its SubAck is swallowed: nothing new on the socket.
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0031},
                                     indra_brokerlink:encode_suback_meta(7, [1]), <<>>),
        ?assertMatch({connected, _}, wait_state(Conn, connected)),
        ?assertEqual({error, timeout}, gen_tcp:recv(Client, 0, 300))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

pingreq_answered_while_holding_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6204}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-ping-hold">>, Conn),
        gen_statem:cast(Conn, {broker_down}),
        ?assertMatch({await_core, _}, wait_state(Conn, await_core)),
        %% Edge PINGRESP keeps the peer keepalive alive across the outage.
        ok = gen_tcp:send(Client, <<16#C0, 16#00>>),
        ?assertEqual(<<16#D0, 16#00>>, recv_exact(Client, 2)),
        ?assertMatch({await_core, _}, sys:get_state(Conn)),
        %% No broker traffic was generated for the ping.
        ?assertEqual(1, length(mock_broker:sent(Mock)))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

client_bytes_buffered_during_outage_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6205}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-buf">>, Conn),
        gen_statem:cast(Conn, {broker_down}),
        ?assertMatch({await_core, _}, wait_state(Conn, await_core)),
        %% PUBLISH during the outage: buffered, nothing forwarded.
        ok = gen_tcp:send(Client, publish_packet(<<"t">>, 0, 16#30, <<"held">>)),
        timer:sleep(200),
        ?assertEqual(1, length(mock_broker:sent(Mock))),
        %% Core returns with state: drain forwards the held publish.
        gen_statem:cast(Conn, {broker_up, Mock}),
        [_Bind, Rebind] = wait_frames(Mock, 2),
        ?assertEqual(16#0010, maps:get(opcode, Rebind)),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011},
                                     indra_brokerlink:encode_session_binding_meta(7, true, 0),
                                     <<>>),
        ?assertMatch({connected, _}, wait_state(Conn, connected)),
        [_B1, _RB, Pub] = wait_frames(Mock, 3),
        ?assertEqual(16#0020, maps:get(opcode, Pub)),
        ?assertEqual(<<"held">>, maps:get(payload, Pub))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

duplicate_broker_up_ignored_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6206}]),
    _ = Port,
    try
        handshake(Client, Mock, <<"dev-dup">>, Conn),
        %% Same broker identity re-announced: no spurious rebind.
        gen_statem:cast(Conn, {broker_up, Mock}),
        timer:sleep(200),
        ?assertEqual(1, length(mock_broker:sent(Mock))),
        ?assertMatch({connected, _}, sys:get_state(Conn))
    after
        teardown(LSock, Mock, Client, Conn)
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

%% @private Poll a gen_statem until it reaches State (async transitions).
wait_state(Pid, State) ->
    wait_state(Pid, State, 40).

wait_state(_Pid, _State, 0) ->
    error(state_timeout);
wait_state(Pid, State, Tries) ->
    case sys:get_state(Pid) of
        {State, Data} -> {State, Data};
        _ -> timer:sleep(50), wait_state(Pid, State, Tries - 1)
    end.

%% @private Minimal MQTT 3.1.1 CONNECT (remaining length < 128 bytes).
connect_packet(ClientId, CleanStart, Keepalive) ->
    Flags = case CleanStart of true -> 16#02; false -> 16#00 end,
    connect_packet_raw(ClientId, Flags, Keepalive).
connect_packet_raw(ClientId, Flags, Keepalive) ->
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.

%% @private CONNECT with username + password credentials.
connect_packet_creds(ClientId, User, Pass) ->
    Var = <<0, 4, "MQTT", 4, 16#C2, 0, 60>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary,
                (byte_size(User)):16/big, User/binary,
                (byte_size(Pass)):16/big, Pass/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.

%% @private Run CONNECT -> CONNACK against the mock broker.
handshake(Client, Mock, ClientId, Conn) ->
    ok = gen_tcp:send(Client, connect_packet(ClientId, true, 60)),
    [_Bind] = wait_frames(Mock, 1),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = recv_exact(Client, 4),
    ok.

%% @private Minimal MQTT SUBSCRIBE (remaining length < 128 bytes).
subscribe_packet(PacketId, Filters) ->
    Subs = lists:foldl(
        fun({Filter, QoS}, Acc) ->
            <<Acc/binary, (byte_size(Filter)):16/big, Filter/binary, QoS:8>>
        end, <<>>, Filters),
    Body = <<PacketId:16/big, Subs/binary>>,
    <<16#82, (byte_size(Body)), Body/binary>>.

%% @private Minimal MQTT PUBLISH (remaining length < 128 bytes).
publish_packet(Topic, PacketId, Flags, Payload) ->
    Var = case (Flags band 16#06) bsr 1 of
        0 -> <<(byte_size(Topic)):16/big, Topic/binary>>;
        _ -> <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big>>
    end,
    Body = <<Var/binary, Payload/binary>>,
    <<3:4, Flags:4, (byte_size(Body)), Body/binary>>.

%% @private Read whatever the socket currently holds.
recv_all(Sock) ->
    {ok, Bin} = gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT),
    Bin.
