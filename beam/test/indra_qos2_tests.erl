%% @doc EUnit tests for QoS 2 exactly-once on the BEAM edge (D1-01).
%%
%% Covers both directions through {@link indra_conn}: inbound (client
%% PUBLISH QoS 2 -> PUBREC -> PUBREL -> PUBCOMP) including a duplicate
%% PUBLISH before PUBREL, and outbound (kernel PUBLISH QoS 2 -> PUBREC
%% -> PUBREL -> PUBCOMP) including the reconnect resend with DUP set.
%% Codec and BrokerLink metadata contracts are covered alongside the
%% connection flow so the four-packet exchange is pinned end to end.
-module(indra_qos2_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).

%%====================================================================
%% Codec
%%====================================================================

codec_pubrec_roundtrip_test() ->
    Bin = indra_mqtt_codec:encode_pubrec(77),
    ?assertEqual(<<16#50, 16#02, 16#00, 16#4D>>, Bin),
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(pubrec, maps:get(type_atom, Pkt)),
    ?assertEqual(<<16#00, 16#4D>>, maps:get(payload, Pkt)).

codec_pubrel_roundtrip_test() ->
    Bin = indra_mqtt_codec:encode_pubrel(77),
    ?assertEqual(<<16#62, 16#02, 16#00, 16#4D>>, Bin),
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(pubrel, maps:get(type_atom, Pkt)).

codec_pubcomp_roundtrip_test() ->
    Bin = indra_mqtt_codec:encode_pubcomp(77),
    ?assertEqual(<<16#70, 16#02, 16#00, 16#4D>>, Bin),
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(pubcomp, maps:get(type_atom, Pkt)).

%%====================================================================
%% BrokerLink metadata
%%====================================================================

brokerlink_qos2_meta_roundtrip_test() ->
    Rec = indra_brokerlink:encode_pubrec_meta(60001),
    ?assertEqual({ok, #{packet_id => 60001}}, indra_brokerlink:decode_pubrec_meta(Rec)),
    Rel = indra_brokerlink:encode_pubrel_meta(7),
    ?assertEqual({ok, #{packet_id => 7}}, indra_brokerlink:decode_pubrel_meta(Rel)),
    Comp = indra_brokerlink:encode_pubcomp_meta(9),
    ?assertEqual({ok, #{packet_id => 9}}, indra_brokerlink:decode_pubcomp_meta(Comp)),
    ?assertEqual({error, malformed_pubrec_meta}, indra_brokerlink:decode_pubrec_meta(<<0, 0>>)),
    ?assertEqual({error, malformed_pubrel_meta}, indra_brokerlink:decode_pubrel_meta(<<>>)),
    ?assertEqual({error, malformed_pubcomp_meta}, indra_brokerlink:decode_pubcomp_meta(<<0, 0>>)).

%%====================================================================
%% Inbound (client publishes at QoS 2)
%%====================================================================

inbound_qos2_four_packet_flow_test() ->
    {LSock, _Port, Mock, Client, Conn} = setup([{conn_id, 7101}]),
    try
        handshake(Client, Mock, <<"q2-pub">>, Conn),
        %% Client PUBLISH QoS 2 packet 77.
        ok = gen_tcp:send(Client, publish_packet(<<"t">>, 77, 16#34, <<"once">>)),
        [_Bind, Pub] = wait_frames(Mock, 2),
        ?assertEqual(16#0020, maps:get(opcode, Pub)),
        {ok, PubMeta} = indra_brokerlink:decode_publish_meta(maps:get(meta, Pub)),
        ?assertEqual(77, maps:get(packet_id, PubMeta)),
        ?assertEqual(2, maps:get(qos, PubMeta)),
        {connected, Data0} = sys:get_state(Conn),
        ?assert(maps:is_key(77, maps:get(qos2_pending, Data0))),
        %% Kernel PUBREC -> client PUBREC.
        RecMeta = indra_brokerlink:encode_pubrec_meta(77),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0025}, RecMeta, <<>>),
        ?assertEqual(indra_mqtt_codec:encode_pubrec(77), recv_exact(Client, 4)),
        %% Pending stays until PUBCOMP.
        {connected, Data1} = sys:get_state(Conn),
        ?assert(maps:is_key(77, maps:get(qos2_pending, Data1))),
        %% Client PUBREL -> kernel PubRelIn.
        ok = gen_tcp:send(Client, indra_mqtt_codec:encode_pubrel(77)),
        [_B, _P, Rel] = wait_frames(Mock, 3),
        ?assertEqual(16#0026, maps:get(opcode, Rel)),
        {ok, RelMeta} = indra_brokerlink:decode_pubrel_meta(maps:get(meta, Rel)),
        ?assertEqual(77, maps:get(packet_id, RelMeta)),
        %% Kernel PUBCOMP -> client PUBCOMP, pending released.
        CompMeta = indra_brokerlink:encode_pubcomp_meta(77),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0029}, CompMeta, <<>>),
        ?assertEqual(indra_mqtt_codec:encode_pubcomp(77), recv_exact(Client, 4)),
        {connected, Data2} = sys:get_state(Conn),
        ?assertNot(maps:is_key(77, maps:get(qos2_pending, Data2)))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

inbound_qos2_duplicate_publish_forwards_again_test() ->
    {LSock, _Port, Mock, Client, Conn} = setup([{conn_id, 7102}]),
    try
        handshake(Client, Mock, <<"q2-dup">>, Conn),
        ok = gen_tcp:send(Client, publish_packet(<<"t">>, 9, 16#34, <<"dup">>)),
        [_Bind, _Pub] = wait_frames(Mock, 2),
        %% Duplicate PUBLISH with DUP=1 and the same packet id: the edge
        %% still forwards so the kernel can reply PUBREC again.
        ok = gen_tcp:send(Client, publish_packet(<<"t">>, 9, 16#3C, <<"dup">>)),
        [_B, _P, Dup] = wait_frames(Mock, 3),
        ?assertEqual(16#0020, maps:get(opcode, Dup)),
        {ok, DupMeta} = indra_brokerlink:decode_publish_meta(maps:get(meta, Dup)),
        ?assertEqual(9, maps:get(packet_id, DupMeta)),
        ?assertEqual(true, maps:get(dup, DupMeta)),
        %% Kernel PUBREC for the duplicate still reaches the client.
        RecMeta = indra_brokerlink:encode_pubrec_meta(9),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0025}, RecMeta, <<>>),
        ?assertEqual(indra_mqtt_codec:encode_pubrec(9), recv_exact(Client, 4))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

%%====================================================================
%% Outbound (broker delivers at QoS 2)
%%====================================================================

outbound_qos2_four_packet_flow_test() ->
    {LSock, _Port, Mock, Client, Conn} = setup([{conn_id, 7201}]),
    try
        handshake(Client, Mock, <<"q2-sub">>, Conn),
        %% Kernel PUBLISH QoS 2 packet 99.
        Meta = indra_brokerlink:encode_publish_meta(<<"t">>, 99, 2, false, false),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0021}, Meta, <<"live">>),
        {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(recv_all(Client)),
        ?assertEqual(publish, maps:get(type_atom, Pkt)),
        {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                    maps:get(flags, Pkt)),
        ?assertEqual(99, maps:get(packet_id, Pub)),
        ?assertEqual(2, maps:get(qos, Pub)),
        ?assertEqual(false, maps:get(dup, Pub)),
        %% Client PUBREC -> kernel PubRecIn.
        ok = gen_tcp:send(Client, <<16#50, 16#02, 16#00, 16#63>>),
        [_Bind, Ack] = wait_frames(Mock, 2),
        ?assertEqual(16#0024, maps:get(opcode, Ack)),
        {ok, AckMeta} = indra_brokerlink:decode_pubrec_meta(maps:get(meta, Ack)),
        ?assertEqual(99, maps:get(packet_id, AckMeta)),
        %% Kernel PUBREL -> client PUBREL.
        RelMeta = indra_brokerlink:encode_pubrel_meta(99),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0027}, RelMeta, <<>>),
        ?assertEqual(indra_mqtt_codec:encode_pubrel(99), recv_exact(Client, 4)),
        %% Client PUBCOMP -> kernel PubCompIn.
        ok = gen_tcp:send(Client, indra_mqtt_codec:encode_pubcomp(99)),
        [_B, _A, Comp] = wait_frames(Mock, 3),
        ?assertEqual(16#0028, maps:get(opcode, Comp)),
        {ok, CompMeta} = indra_brokerlink:decode_pubcomp_meta(maps:get(meta, Comp)),
        ?assertEqual(99, maps:get(packet_id, CompMeta))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

outbound_qos2_reconnect_resend_sets_dup_test() ->
    {LSock, _Port, _Mock, Client, Conn} = setup([{conn_id, 7202}]),
    try
        handshake(Client, _Mock, <<"q2-resend">>, Conn),
        %% Kernel replay after reconnect carries DUP=1: the client must
        %% observe a PUBLISH with the DUP flag set and the same id.
        Meta = indra_brokerlink:encode_publish_meta(<<"t">>, 55, 2, false, true),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0021}, Meta, <<"again">>),
        {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(recv_all(Client)),
        {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                    maps:get(flags, Pkt)),
        ?assertEqual(55, maps:get(packet_id, Pub)),
        ?assertEqual(2, maps:get(qos, Pub)),
        ?assertEqual(true, maps:get(dup, Pub)),
        ?assertEqual(<<"again">>, maps:get(payload, Pub))
    after
        teardown(LSock, _Mock, Client, Conn)
    end.

%%====================================================================
%% Helpers
%%====================================================================

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

recv_all(Sock) ->
    {ok, Bin} = gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT),
    Bin.

handshake(Client, Mock, ClientId, Conn) ->
    ok = gen_tcp:send(Client, connect_packet(ClientId, true, 60)),
    [_Bind] = wait_frames(Mock, 1),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = recv_exact(Client, 4),
    ok.

connect_packet(ClientId, CleanStart, Keepalive) ->
    Flags = case CleanStart of true -> 16#02; false -> 16#00 end,
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.

publish_packet(Topic, PacketId, Flags, Payload) ->
    Var = case (Flags band 16#06) bsr 1 of
        0 -> <<(byte_size(Topic)):16/big, Topic/binary>>;
        _ -> <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big>>
    end,
    Body = <<Var/binary, Payload/binary>>,
    <<3:4, Flags:4, (byte_size(Body)), Body/binary>>.
