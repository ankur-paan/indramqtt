%% @doc EUnit tests for {@link indra_listener}.
%%
%% Self-terminating integration coverage: the listener binds an
%% ephemeral port, accepts a real client socket into a real
%% `indra_conn`, and completes the CONNECT -> CONNACK handshake against
%% {@link mock_broker}. Nothing outlives the test.
-module(indra_listener_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).

start_stop_ephemeral_test() ->
    {ok, Listener} = indra_listener:start_link([{port, 0}]),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        ?assert(Port > 0),
        %% A client can open (and close) a TCP connection.
        {ok, Sock} = gen_tcp:connect("127.0.0.1", Port,
                                     [binary, {packet, raw}, {active, false}],
                                     2000),
        gen_tcp:close(Sock)
    after
        indra_listener:stop(Listener)
    end,
    %% After stop the port is closed again.
    {ok, Probe} = indra_listener:start_link([{port, 0}]),
    {ok, Port2} = indra_listener:get_port(Probe),
    indra_listener:stop(Probe),
    ?assertMatch({error, _},
                 gen_tcp:connect("127.0.0.1", Port2,
                                 [binary, {packet, raw}, {active, false}],
                                 500)).

tls_connect_connack_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_listener:start_link([{transport, ssl},
                                                {port, 0},
                                                {certfile, Cert},
                                                {keyfile, Key},
                                                {conn, [{broker, Mock},
                                                        {transport, ssl},
                                                        {conn_id, 9101}]}]),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        {ok, Client} = ssl:connect("127.0.0.1", Port,
                                   [binary, {packet, raw},
                                    {active, false}, {verify, verify_none}],
                                   5000),
        try
            ok = ssl:send(Client, connect_packet(<<"tls-dev">>, true, 60)),
            [Sent] = wait_frames(Mock, 1),
            ?assertEqual(16#0010, maps:get(opcode, Sent)),
            ?assertEqual(9101, maps:get(conn_id, Sent)),
            {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Sent)),
            ?assertEqual(<<"tls-dev">>, maps:get(client_id, Bind)),
            Conn = maps:get(from, Sent),
            Binding = indra_brokerlink:encode_session_binding_meta(4242, false, 0),
            ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
            {ok, Connack} = ssl:recv(Client, 4, ?RECV_TIMEOUT),
            ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>, Connack),
            ?assertMatch({connected, _}, sys:get_state(Conn))
        after
            ssl:close(Client)
        end
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

tls_missing_keyfile_rejected_test() ->
    {Cert, _Key} = test_certs(),
    process_flag(trap_exit, true),
    try
        ?assertMatch({error, _},
                     indra_listener:start_link([{transport, ssl},
                                                {port, 0},
                                                {certfile, Cert}])),
        receive {'EXIT', _, _} -> ok after 1000 -> ok end
    after
        process_flag(trap_exit, false)
    end.

full_handshake_through_listener_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_listener:start_link([{port, 0},
                                                {conn, [{broker, Mock},
                                                        {conn_id, 9001}]}]),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        {ok, Client} = gen_tcp:connect("127.0.0.1", Port,
                                       [binary, {packet, raw}, {active, false}],
                                       2000),
        try
            ok = gen_tcp:send(Client, connect_packet(<<"via-listener">>, true, 60)),
            [Sent] = wait_frames(Mock, 1),
            ?assertEqual(16#0010, maps:get(opcode, Sent)),
            ?assertEqual(9001, maps:get(conn_id, Sent)),
            {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Sent)),
            ?assertEqual(<<"via-listener">>, maps:get(client_id, Bind)),
            %% The conn under test is the frame sender; answer it directly.
            Conn = maps:get(from, Sent),
            Binding = indra_brokerlink:encode_session_binding_meta(4242, true, 0),
            ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
            {ok, Connack} = gen_tcp:recv(Client, 4, ?RECV_TIMEOUT),
            ?assertEqual(<<16#20, 16#02, 16#01, 16#00>>, Connack),
            ?assertMatch({connected, _}, sys:get_state(Conn))
        after
            gen_tcp:close(Client)
        end
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc Two real clients, one listener, mock core playing Rust:
%% A subscribes, B publishes (QoS 0 then QoS 1), A receives both and B
%% gets its PUBACK. Proves the BEAM delivery loop end to end.
pubsub_loop_two_clients_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_listener:start_link([{port, 0},
                                                {conn, [{broker, Mock}]}]),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        {ok, ClientA} = gen_tcp:connect("127.0.0.1", Port,
                                        [binary, {packet, raw}, {active, false}],
                                        2000),
        {ok, ClientB} = gen_tcp:connect("127.0.0.1", Port,
                                        [binary, {packet, raw}, {active, false}],
                                        2000),
        try
            {APid, AConn} = handshake(ClientA, Mock, <<"client-a">>),
            {BPid, BConn} = handshake(ClientB, Mock, <<"client-b">>),
            %% A subscribes to sport/tennis at QoS 1.
            ok = gen_tcp:send(ClientA, subscribe_packet(7, [{<<"sport/tennis">>, 1}])),
            Sub = wait_frame(Mock, APid, 16#0030),
            {ok, SubMeta} = indra_brokerlink:decode_subscribe_meta(maps:get(meta, Sub)),
            ?assertEqual(7, maps:get(packet_id, SubMeta)),
            ?assertEqual(<<"client-a">>, maps:get(client_id, SubMeta)),
            ok = indra_conn:broker_frame(
                   APid, #{opcode => 16#0031},
                   indra_brokerlink:encode_suback_meta(7, [1]), <<>>),
            ?assertEqual(<<16#90, 16#03, 16#00, 16#07, 16#01>>,
                         recv_exact(ClientA, 5)),
            %% B publishes QoS 0: A receives it, B gets no ack.
            ok = gen_tcp:send(ClientB, publish_packet(<<"sport/tennis">>, 0, 16#30, <<"hello">>)),
            Pub0 = wait_frame(Mock, BPid, 16#0020),
            {ok, Pub0Meta} = indra_brokerlink:decode_publish_meta(maps:get(meta, Pub0)),
            ?assertEqual(<<"sport/tennis">>, maps:get(topic, Pub0Meta)),
            ?assertEqual(<<"hello">>, maps:get(payload, Pub0)),
            Out0 = indra_brokerlink:encode_publish_meta(<<"sport/tennis">>, 0, 0, false, false),
            ok = indra_conn:broker_frame(
                   APid, #{opcode => 16#0021, conn_id => AConn}, Out0, <<"hello">>),
            assert_mqtt_publish(ClientA, <<"sport/tennis">>, 0, 0, <<"hello">>),
            %% B publishes QoS 1: B gets PUBACK, A gets the delivery.
            ok = gen_tcp:send(ClientB, publish_packet(<<"sport/tennis">>, 42, 16#32, <<"again">>)),
            Pub1 = wait_frame(Mock, BPid, 16#0020, 2),
            {ok, Pub1Meta} = indra_brokerlink:decode_publish_meta(maps:get(meta, Pub1)),
            ?assertEqual(42, maps:get(packet_id, Pub1Meta)),
            ok = indra_conn:broker_frame(
                   BPid, #{opcode => 16#0023},
                   indra_brokerlink:encode_puback_meta(42, 0), <<>>),
            ?assertEqual(<<16#40, 16#02, 16#00, 16#2A>>,
                         recv_exact(ClientB, 4)),
            Out1 = indra_brokerlink:encode_publish_meta(<<"sport/tennis">>, 77, 1, false, false),
            ok = indra_conn:broker_frame(
                   APid, #{opcode => 16#0021, conn_id => AConn}, Out1, <<"again">>),
            assert_mqtt_publish(ClientA, <<"sport/tennis">>, 77, 1, <<"again">>),
            _ = BConn,
            ok
        after
            gen_tcp:close(ClientA),
            gen_tcp:close(ClientB)
        end
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%%====================================================================
%% Helpers
%%====================================================================

wait_frames(_Mock, _N, 0) ->
    error(broker_frame_timeout);
wait_frames(Mock, N, Tries) ->
    case mock_broker:sent(Mock) of
        Frames when length(Frames) >= N -> Frames;
        _ -> timer:sleep(50), wait_frames(Mock, N, Tries - 1)
    end.

wait_frames(Mock, N) ->
    wait_frames(Mock, N, 40).

%% @private Wait for a frame with Opcode sent by Pid (Nth such frame).
wait_frame(Mock, Pid, Opcode) ->
    wait_frame(Mock, Pid, Opcode, 1, 40).

wait_frame(Mock, Pid, Opcode, N) ->
    wait_frame(Mock, Pid, Opcode, N, 40).

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

recv_exact(Sock, N) ->
    {ok, Bin} = gen_tcp:recv(Sock, N, ?RECV_TIMEOUT),
    Bin.

%% @private CONNECT the client and complete the handshake; returns the
%% conn pid and its BrokerLink conn id.
handshake(Client, Mock, ClientId) ->
    ok = gen_tcp:send(Client, connect_packet(ClientId, true, 60)),
    Bind = wait_bind(Mock, ClientId, 40),
    Conn = maps:get(from, Bind),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = recv_exact(Client, 4),
    {Conn, maps:get(conn_id, Bind)}.

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

%% @private Assert one MQTT PUBLISH arrives with the expected fields.
assert_mqtt_publish(Client, Topic, PacketId, QoS, Payload) ->
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(recv_all(Client)),
    ?assertEqual(publish, maps:get(type_atom, Pkt)),
    {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                maps:get(flags, Pkt)),
    ?assertEqual(Topic, maps:get(topic, Pub)),
    ?assertEqual(PacketId, maps:get(packet_id, Pub)),
    ?assertEqual(QoS, maps:get(qos, Pub)),
    ?assertEqual(Payload, maps:get(payload, Pub)),
    ok.

recv_all(Sock) ->
    {ok, Bin} = gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT),
    Bin.

connect_packet(ClientId, CleanStart, Keepalive) ->
    Flags = case CleanStart of true -> 16#02; false -> 16#00 end,
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
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
%% suite runs from `beam/` (rebar3) or the repo root (erl runner).
test_certs() ->
    Candidates = [{"test/certs/cert.pem", "test/certs/key.pem"},
                  {"beam/test/certs/cert.pem", "beam/test/certs/key.pem"}],
    case lists:dropwhile(
           fun({C, K}) ->
               filelib:is_regular(C) =:= false orelse filelib:is_regular(K) =:= false
           end, Candidates) of
        [{C, K} | _] -> {C, K};
        [] -> error({missing_test_certs, Candidates})
    end.
