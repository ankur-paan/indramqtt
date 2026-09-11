%% @doc EUnit tests for {@link indra_brokerlink}.
-module(indra_brokerlink_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Encoding
%%====================================================================

encode_ping_exact_bytes_test() ->
    Bin = indra_brokerlink:encode_frame(16#0001, 0, 0, <<>>, <<>>),
    ?assertEqual(28, byte_size(Bin)),
    ?assertEqual(<<16#42, 16#4C, 1, 0,
                   16#0001:16/big,
                   0:64/big,
                   0:64/big,
                   0:16/big,
                   0:32/big>>, Bin).

encode_header_fields_big_endian_test() ->
    ConnId = 16#0102030405060708,
    SeqNo = 16#1112131415161718,
    Bin = indra_brokerlink:encode_frame(publish_in, ConnId, SeqNo, <<"AB">>, <<"xyz">>),
    %% 28 header + 2 meta + 3 payload
    ?assertEqual(33, byte_size(Bin)),
    <<16#42, 16#4C, Ver, Flags,
      Op:16/big, C:64/big, S:64/big, ML:16/big, PL:32/big,
      Meta:2/binary, Payload:3/binary>> = Bin,
    ?assertEqual(1, Ver),
    ?assertEqual(0, Flags),
    ?assertEqual(16#0020, Op),
    ?assertEqual(ConnId, C),
    ?assertEqual(SeqNo, S),
    ?assertEqual(2, ML),
    ?assertEqual(3, PL),
    ?assertEqual(<<"AB">>, Meta),
    ?assertEqual(<<"xyz">>, Payload).

encode_atom_and_int_opcodes_agree_test() ->
    A = indra_brokerlink:encode_frame(ping, 7, 9, <<>>, <<>>),
    B = indra_brokerlink:encode_frame(16#0001, 7, 9, <<>>, <<>>),
    ?assertEqual(A, B),
    ?assertEqual(indra_brokerlink:encode_frame(pong, 1, 1, <<>>, <<>>),
                 indra_brokerlink:encode_frame(16#0002, 1, 1, <<>>, <<>>)),
    ?assertEqual(indra_brokerlink:encode_frame(bind_connection, 1, 1, <<>>, <<>>),
                 indra_brokerlink:encode_frame(16#0010, 1, 1, <<>>, <<>>)),
    ?assertEqual(indra_brokerlink:encode_frame(session_binding, 1, 1, <<>>, <<>>),
                 indra_brokerlink:encode_frame(16#0011, 1, 1, <<>>, <<>>)),
    ?assertEqual(indra_brokerlink:encode_frame(publish_out, 1, 1, <<>>, <<>>),
                 indra_brokerlink:encode_frame(16#0021, 1, 1, <<>>, <<>>)).

encode_max_u64_ids_test() ->
    Max = 16#FFFFFFFFFFFFFFFF,
    Bin = indra_brokerlink:encode_frame(ping, Max, Max, <<>>, <<>>),
    {ok, Header, <<>>, <<>>, <<>>} = indra_brokerlink:decode_frame(Bin),
    ?assertEqual(Max, maps:get(conn_id, Header)),
    ?assertEqual(Max, maps:get(seq_no, Header)).

encode_meta_too_large_raises_test() ->
    Big = binary:copy(<<"x">>, 65536),
    ?assertError(badarg,
                 indra_brokerlink:encode_frame(ping, 1, 1, Big, <<>>)).

%%====================================================================
%% Decoding round-trips
%%====================================================================

roundtrip_with_meta_and_payload_test() ->
    Meta = <<"meta-bytes">>,
    Payload = <<"{\"temp\":23.4}">>,
    Bin = indra_brokerlink:encode_frame(16#0020, 987654321, 1, Meta, Payload),
    {ok, Header, MetaOut, PayloadOut, Rest} = indra_brokerlink:decode_frame(Bin),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(1, maps:get(version, Header)),
    ?assertEqual(0, maps:get(flags, Header)),
    ?assertEqual(16#0020, maps:get(opcode, Header)),
    ?assertEqual(987654321, maps:get(conn_id, Header)),
    ?assertEqual(1, maps:get(seq_no, Header)),
    ?assertEqual(byte_size(Meta), maps:get(meta_len, Header)),
    ?assertEqual(byte_size(Payload), maps:get(payload_len, Header)),
    ?assertEqual(Meta, MetaOut),
    ?assertEqual(Payload, PayloadOut).

roundtrip_empty_meta_payload_test() ->
    Bin = indra_brokerlink:encode_frame(ping, 42, 100, <<>>, <<>>),
    {ok, Header, Meta, Payload, Rest} = indra_brokerlink:decode_frame(Bin),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(<<>>, Meta),
    ?assertEqual(<<>>, Payload),
    ?assertEqual(16#0001, maps:get(opcode, Header)),
    ?assertEqual(42, maps:get(conn_id, Header)),
    ?assertEqual(100, maps:get(seq_no, Header)).

two_frames_concatenated_test() ->
    A = indra_brokerlink:encode_frame(ping, 1, 1, <<>>, <<>>),
    B = indra_brokerlink:encode_frame(pong, 2, 2, <<"m">>, <<"p">>),
    Both = <<A/binary, B/binary>>,
    {ok, HA, <<>>, <<>>, Rest} = indra_brokerlink:decode_frame(Both),
    ?assertEqual(16#0001, maps:get(opcode, HA)),
    {ok, HB, MetaB, PayB, Rest2} = indra_brokerlink:decode_frame(Rest),
    ?assertEqual(<<>>, Rest2),
    ?assertEqual(16#0002, maps:get(opcode, HB)),
    ?assertEqual(<<"m">>, MetaB),
    ?assertEqual(<<"p">>, PayB).

%%====================================================================
%% Fragmentation / streaming
%%====================================================================

short_header_needs_more_test() ->
    ?assertEqual({more, 28}, indra_brokerlink:decode_frame(<<>>)),
    ?assertEqual({more, 18}, indra_brokerlink:decode_frame(binary:copy(<<0>>, 10))),
    ?assertEqual({more, 1}, indra_brokerlink:decode_frame(binary:copy(<<0>>, 27))).

split_body_needs_more_test() ->
    Meta = <<"meta">>,
    Payload = <<"payload-data-stream">>,
    Bin = indra_brokerlink:encode_frame(publish_out, 42, 100, Meta, Payload),
    Total = byte_size(Bin),
    %% Header only: still need the full body.
    HeaderOnly = binary:part(Bin, 0, 28),
    BodyLen = byte_size(Meta) + byte_size(Payload),
    ?assertEqual({more, BodyLen}, indra_brokerlink:decode_frame(HeaderOnly)),
    %% Header + 1 body byte: need the remainder.
    Partial = binary:part(Bin, 0, 29),
    ?assertEqual({more, Total - 29}, indra_brokerlink:decode_frame(Partial)).

byte_by_byte_reassembly_test() ->
    Bin = indra_brokerlink:encode_frame(publish_out, 42, 100, <<"meta">>, <<"payload-data">>),
    Total = byte_size(Bin),
    %% Feed all but the last byte: must always report {more, _}.
    lists:foreach(
      fun(N) ->
          Prefix = binary:part(Bin, 0, N),
          ?assertMatch({more, _}, indra_brokerlink:decode_frame(Prefix))
      end, lists:seq(0, Total - 1)),
    %% Full buffer decodes.
    {ok, Header, Meta, Payload, <<>>} = indra_brokerlink:decode_frame(Bin),
    ?assertEqual(16#0021, maps:get(opcode, Header)),
    ?assertEqual(<<"meta">>, Meta),
    ?assertEqual(<<"payload-data">>, Payload).

halves_reassembly_test() ->
    Bin = indra_brokerlink:encode_frame(bind_connection, 99, 7, <<"m1">>, <<"p1p1">>),
    Half = byte_size(Bin) div 2,
    First = binary:part(Bin, 0, Half),
    ?assertMatch({more, _}, indra_brokerlink:decode_frame(First)),
    %% Simulate a reassembly buffer: append the second half.
    Second = binary:part(Bin, Half, byte_size(Bin) - Half),
    {ok, Header, <<"m1">>, <<"p1p1">>, <<>>} =
        indra_brokerlink:decode_frame(<<First/binary, Second/binary>>),
    ?assertEqual(16#0010, maps:get(opcode, Header)),
    ?assertEqual(99, maps:get(conn_id, Header)),
    ?assertEqual(7, maps:get(seq_no, Header)).

%%====================================================================
%% Corruption rejection
%%====================================================================

corrupted_magic_rejected_test() ->
    Good = indra_brokerlink:encode_frame(ping, 1, 1, <<>>, <<>>),
    <<_:2/binary, Tail/binary>> = Good,
    Bad = <<16#00, 16#00, Tail/binary>>,
    ?assertEqual({error, {invalid_magic, 16#00, 16#00}},
                 indra_brokerlink:decode_frame(Bad)).

unsupported_version_rejected_test() ->
    Good = indra_brokerlink:encode_frame(ping, 1, 1, <<>>, <<>>),
    <<M0, M1, _Ver, Rest/binary>> = Good,
    Bad = <<M0, M1, 99, Rest/binary>>,
    ?assertEqual({error, {unsupported_version, 99}},
                 indra_brokerlink:decode_frame(Bad)).

unknown_opcode_rejected_test() ->
    Good = indra_brokerlink:encode_frame(ping, 1, 1, <<>>, <<>>),
    <<Magic:2/binary, Ver, Flags, _Op:16/big, Tail/binary>> = Good,
    Bad = <<Magic/binary, Ver, Flags, 16#FFFF:16/big, Tail/binary>>,
    ?assertEqual({error, {unknown_opcode, 16#FFFF}},
                 indra_brokerlink:decode_frame(Bad)).

opcode_mapping_helpers_test() ->
    ?assertEqual(16#0001, indra_brokerlink:opcode_to_int(ping)),
    ?assertEqual(16#0002, indra_brokerlink:opcode_to_int(pong)),
    ?assertEqual(16#0010, indra_brokerlink:opcode_to_int(bind_connection)),
    ?assertEqual(16#0011, indra_brokerlink:opcode_to_int(session_binding)),
    ?assertEqual(16#0020, indra_brokerlink:opcode_to_int(publish_in)),
    ?assertEqual(16#0021, indra_brokerlink:opcode_to_int(publish_out)),
    ?assertEqual(ping, indra_brokerlink:int_to_opcode(16#0001)),
    ?assertEqual(pong, indra_brokerlink:int_to_opcode(16#0002)),
    ?assertEqual(publish_in, indra_brokerlink:int_to_opcode(16#0020)).

%%====================================================================
%% Sprint 2 metadata contracts
%%====================================================================

bind_meta_roundtrip_test() ->
    Meta = indra_brokerlink:encode_bind_meta(<<"sensor-1">>, true, 60),
    ?assertEqual(<<0, 8, "sensor-1", 1, 0, 60>>, Meta),
    {ok, Dec} = indra_brokerlink:decode_bind_meta(Meta),
    ?assertEqual(<<"sensor-1">>, maps:get(client_id, Dec)),
    ?assertEqual(true, maps:get(clean_start, Dec)),
    ?assertEqual(60, maps:get(keepalive, Dec)).

bind_meta_clean_start_false_test() ->
    Meta = indra_brokerlink:encode_bind_meta(<<"d">>, false, 0),
    {ok, Dec} = indra_brokerlink:decode_bind_meta(Meta),
    ?assertEqual(false, maps:get(clean_start, Dec)),
    ?assertEqual(0, maps:get(keepalive, Dec)).

bind_meta_max_keepalive_test() ->
    Meta = indra_brokerlink:encode_bind_meta(<<>>, true, 65535),
    {ok, Dec} = indra_brokerlink:decode_bind_meta(Meta),
    ?assertEqual(<<>>, maps:get(client_id, Dec)),
    ?assertEqual(65535, maps:get(keepalive, Dec)).

bind_meta_malformed_rejected_test() ->
    ?assertEqual({error, malformed_bind_meta},
                 indra_brokerlink:decode_bind_meta(<<>>)),
    ?assertEqual({error, malformed_bind_meta},
                 indra_brokerlink:decode_bind_meta(<<0, 5, "ab">>)),
    %% Declared length longer than the bytes present.
    ?assertEqual({error, malformed_bind_meta},
                 indra_brokerlink:decode_bind_meta(<<0, 9, "short">>)).

session_binding_meta_roundtrip_test() ->
    Meta = indra_brokerlink:encode_session_binding_meta(16#0102030405060708, true, 0),
    ?assertEqual(<<16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08, 1, 0>>,
                 Meta),
    {ok, Dec} = indra_brokerlink:decode_session_binding_meta(Meta),
    ?assertEqual(16#0102030405060708, maps:get(session_id, Dec)),
    ?assertEqual(true, maps:get(session_present, Dec)),
    ?assertEqual(0, maps:get(return_code, Dec)).

session_binding_absent_with_rc_test() ->
    Meta = indra_brokerlink:encode_session_binding_meta(0, false, 2),
    {ok, Dec} = indra_brokerlink:decode_session_binding_meta(Meta),
    ?assertEqual(false, maps:get(session_present, Dec)),
    ?assertEqual(2, maps:get(return_code, Dec)).

session_binding_malformed_rejected_test() ->
    ?assertEqual({error, malformed_session_binding_meta},
                 indra_brokerlink:decode_session_binding_meta(<<0, 1, 2>>)),
    ?assertEqual({error, malformed_session_binding_meta},
                 indra_brokerlink:decode_session_binding_meta(<<0:64, 2, 0>>)).

%%====================================================================
%% Sprint 3 messaging metadata contracts
%%====================================================================

subscribe_meta_roundtrip_test() ->
    Subs = [{<<"sport/tennis">>, 1}, {<<"news">>, 0}],
    Meta = indra_brokerlink:encode_subscribe_meta(7, <<"dev-1">>, Subs),
    {ok, Dec} = indra_brokerlink:decode_subscribe_meta(Meta),
    ?assertEqual(7, maps:get(packet_id, Dec)),
    ?assertEqual(<<"dev-1">>, maps:get(client_id, Dec)),
    ?assertEqual(Subs, maps:get(subscriptions, Dec)).

subscribe_meta_malformed_rejected_test() ->
    ?assertEqual({error, malformed_subscribe_meta},
                 indra_brokerlink:decode_subscribe_meta(<<>>)),
    ?assertEqual({error, malformed_subscribe_meta},
                 indra_brokerlink:decode_subscribe_meta(<<0, 7, 0, 5, "ab">>)),
    %% Zero packet id.
    ?assertEqual({error, malformed_subscribe_meta},
                 indra_brokerlink:decode_subscribe_meta(<<0, 0, 0, 0, 0, 0>>)),
    %% Declared count larger than the entries present.
    ?assertEqual({error, malformed_subscribe_meta},
                 indra_brokerlink:decode_subscribe_meta(
                   <<0, 7, 0, 0, 0, 2, 0, 1, "a", 0>>)),
    %% Empty subscription list rejected at encode time.
    ?assertError(badarg, indra_brokerlink:encode_subscribe_meta(7, <<"d">>, [])),
    %% Bad QoS rejected at encode time.
    ?assertError(badarg,
                 indra_brokerlink:encode_subscribe_meta(7, <<"d">>, [{<<"a">>, 3}])).

suback_meta_roundtrip_test() ->
    Meta = indra_brokerlink:encode_suback_meta(9, [0, 1, 2, 16#80]),
    {ok, Dec} = indra_brokerlink:decode_suback_meta(Meta),
    ?assertEqual(9, maps:get(packet_id, Dec)),
    ?assertEqual([0, 1, 2, 16#80], maps:get(codes, Dec)),
    ?assertEqual({error, malformed_suback_meta},
                 indra_brokerlink:decode_suback_meta(<<0, 0>>)).

publish_meta_roundtrip_test() ->
    Meta = indra_brokerlink:encode_publish_meta(<<"sport/tennis">>, 42, 1, true, false),
    {ok, Dec} = indra_brokerlink:decode_publish_meta(Meta),
    ?assertEqual(<<"sport/tennis">>, maps:get(topic, Dec)),
    ?assertEqual(42, maps:get(packet_id, Dec)),
    ?assertEqual(1, maps:get(qos, Dec)),
    ?assertEqual(true, maps:get(retain, Dec)),
    ?assertEqual(false, maps:get(dup, Dec)).

publish_meta_malformed_rejected_test() ->
    ?assertEqual({error, malformed_publish_meta},
                 indra_brokerlink:decode_publish_meta(<<>>)),
    ?assertEqual({error, malformed_publish_meta},
                 indra_brokerlink:decode_publish_meta(<<0, 0, 0, 0, 0, 0, 0>>)),
    %% Truncated topic bytes.
    ?assertEqual({error, malformed_publish_meta},
                 indra_brokerlink:decode_publish_meta(<<0, 9, "short", 0, 0, 0, 0, 0>>)),
    %% Illegal QoS nibble value.
    ?assertEqual({error, malformed_publish_meta},
                 indra_brokerlink:decode_publish_meta(<<0, 1, "t", 0, 0, 3, 0, 0>>)).

puback_meta_roundtrip_test() ->
    Meta = indra_brokerlink:encode_puback_meta(60000, 0),
    {ok, Dec} = indra_brokerlink:decode_puback_meta(Meta),
    ?assertEqual(60000, maps:get(packet_id, Dec)),
    ?assertEqual(0, maps:get(return_code, Dec)),
    ?assertEqual({error, malformed_puback_meta},
                 indra_brokerlink:decode_puback_meta(<<0, 0>>)).

unbind_meta_roundtrip_test() ->
    Meta = indra_brokerlink:encode_unbind_meta(<<"dev-9">>),
    ?assertEqual({ok, #{client_id => <<"dev-9">>}},
                 indra_brokerlink:decode_unbind_meta(Meta)),
    ?assertEqual({error, malformed_unbind_meta},
                 indra_brokerlink:decode_unbind_meta(<<0, 4, "ab">>)).

%%====================================================================
%% Inbound dispatch through the connection registry (Sprint 3)
%%====================================================================

dispatch_publishout_to_registered_conn_test() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Server = spawn(fun() -> dispatch_server(LSock) end),
    {ok, Registry} = indra_conn_registry:start_link(),
    {ok, Client} = indra_brokerlink:start_link([{transport, tcp},
                                                {host, "127.0.0.1"},
                                                {port, Port}]),
    try
        %% Register the test process as the owner of conn 6101.
        ok = indra_conn_registry:register(6101, self()),
        %% Fake Rust core emits one PublishOut addressed to us.
        Meta = indra_brokerlink:encode_publish_meta(<<"t">>, 0, 0, false, false),
        Frame = indra_brokerlink:encode_frame(16#0021, 6101, 9, Meta, <<"hi">>),
        Server ! {emit, Frame},
        receive
            {'$gen_cast', {broker_frame, Header, GotMeta, GotPayload}} ->
                ?assertEqual(16#0021, maps:get(opcode, Header)),
                ?assertEqual(6101, maps:get(conn_id, Header)),
                ?assertEqual(Meta, GotMeta),
                ?assertEqual(<<"hi">>, GotPayload)
        after 5000 ->
            error(dispatch_timeout)
        end,
        %% After unregister, frames for the conn are dropped silently.
        ok = indra_conn_registry:unregister(6101),
        Server ! {emit, Frame},
        receive
            {'$gen_cast', _} -> error(unexpected_dispatch)
        after 300 ->
            ok
        end
    after
        indra_brokerlink:stop(Client),
        indra_conn_registry:stop(Registry),
        gen_tcp:close(LSock)
    end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

%% @private Minimal fake core: forwards emitted binaries to the acceptor.
dispatch_server(LSock) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} ->
            dispatch_loop(Sock);
        {error, _} ->
            ok
    end.

dispatch_loop(Sock) ->
    receive
        {emit, Bin} ->
            gen_tcp:send(Sock, Bin),
            dispatch_loop(Sock)
    after 8000 ->
        gen_tcp:close(Sock)
    end.

%%====================================================================
%% gen_server IPC behaviour (loopback TCP, no external services)
%%====================================================================

uds_missing_path_rejected_test() ->
    %% start_link links to the caller, so trap the linked exit signal
    %% from the expected init failure.
    process_flag(trap_exit, true),
    try
        ?assertMatch({error, _},
                     indra_brokerlink:start_link([{transport, uds}])),
        receive {'EXIT', _, _} -> ok after 1000 -> ok end
    after
        process_flag(trap_exit, false)
    end.

connect_refused_returns_error_test() ->
    %% Grab an ephemeral port and close it so nothing listens there.
    {ok, LSock} = gen_tcp:listen(0, [{reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    ok = gen_tcp:close(LSock),
    process_flag(trap_exit, true),
    try
        ?assertMatch({error, _},
                     indra_brokerlink:start_link([{transport, tcp},
                                                  {host, "127.0.0.1"},
                                                  {port, Port}])),
        receive {'EXIT', _, _} -> ok after 1000 -> ok end
    after
        process_flag(trap_exit, false)
    end.

ping_sends_framed_ping_over_loopback_test() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Parent = self(),
    _Acceptor = spawn(fun() -> accept_and_forward(LSock, Parent) end),
    {ok, Pid} = indra_brokerlink:start_link([{transport, tcp},
                                             {host, "127.0.0.1"},
                                             {port, Port}]),
    try
        ?assertEqual(ok, indra_brokerlink:ping(Pid, 1234)),
        receive
            {got_frame, Bin} ->
                {ok, Header, Meta, Payload, <<>>} =
                    indra_brokerlink:decode_frame(Bin),
                ?assertEqual(16#0001, maps:get(opcode, Header)),
                ?assertEqual(1234, maps:get(conn_id, Header)),
                ?assertEqual(1, maps:get(seq_no, Header)),
                ?assertEqual(<<>>, Meta),
                ?assertEqual(<<>>, Payload)
        after 5000 ->
            error(ping_frame_timeout)
        end,
        %% Second ping bumps the sequence number.
        ?assertEqual(ok, indra_brokerlink:ping(Pid, 1234)),
        receive
            {got_frame, Bin2} ->
                {ok, Header2, _, _, <<>>} = indra_brokerlink:decode_frame(Bin2),
                ?assertEqual(2, maps:get(seq_no, Header2))
        after 5000 ->
            error(second_ping_timeout)
        end
    after
        indra_brokerlink:stop(Pid),
        gen_tcp:close(LSock)
    end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

accept_and_forward(LSock, Parent) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} ->
            loop_recv(Sock, Parent, <<>>);
        {error, _} ->
            ok
    end.

loop_recv(Sock, Parent, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Data} ->
            Buf = <<Acc/binary, Data/binary>>,
            case indra_brokerlink:decode_frame(Buf) of
                {ok, _H, _M, _P, _R} ->
                    %% Forward each complete frame as it arrives.
                    Parent ! {got_frame, Buf},
                    loop_recv(Sock, Parent, <<>>);
                {more, _} ->
                    loop_recv(Sock, Parent, Buf);
                {error, _} ->
                    ok
            end;
        {error, _} ->
            ok
    end.
