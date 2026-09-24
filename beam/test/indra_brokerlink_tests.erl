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

bind_meta_credentials_roundtrip_test() ->
    Meta = indra_brokerlink:encode_bind_meta(<<"dev-1">>, true, 60,
                                            {<<"alice">>, <<"s3cret">>}),
    {ok, Dec} = indra_brokerlink:decode_bind_meta(Meta),
    ?assertEqual(<<"dev-1">>, maps:get(client_id, Dec)),
    ?assertEqual(true, maps:get(clean_start, Dec)),
    ?assertEqual(60, maps:get(keepalive, Dec)),
    ?assertEqual(<<"alice">>, maps:get(username, Dec)),
    ?assertEqual(<<"s3cret">>, maps:get(password, Dec)).

bind_meta_anonymous_decode_test() ->
    %% Legacy/anonymous encoding carries no credentials section.
    Meta = indra_brokerlink:encode_bind_meta(<<"dev-1">>, false, 30),
    {ok, Dec} = indra_brokerlink:decode_bind_meta(Meta),
    ?assertEqual(undefined, maps:get(username, Dec)),
    ?assertEqual(undefined, maps:get(password, Dec)),
    %% Explicit undefined pair encodes identically to /3.
    ?assertEqual(Meta, indra_brokerlink:encode_bind_meta(<<"dev-1">>, false, 30,
                                                        {undefined, undefined})).

bind_meta_bad_credentials_rejected_test() ->
    %% Truncated credentials section.
    ?assertEqual({error, malformed_bind_meta},
                 indra_brokerlink:decode_bind_meta(<<0, 1, "a", 1, 0, 60, 0, 3, "ab">>)),
    %% Username without password is rejected at encode time.
    ?assertError(badarg,
                 indra_brokerlink:encode_bind_meta(<<"d">>, true, 60,
                                                  {<<"alice">>, undefined})).

bind_meta_peer_roundtrip_test() ->
    %% Credentials plus peer address decode together (B1-03).
    Meta = indra_brokerlink:encode_bind_meta(<<"dev-1">>, true, 60,
                                            {<<"alice">>, <<"s3cret">>},
                                            <<"192.0.2.10">>),
    {ok, Dec} = indra_brokerlink:decode_bind_meta(Meta),
    ?assertEqual(<<"dev-1">>, maps:get(client_id, Dec)),
    ?assertEqual(<<"alice">>, maps:get(username, Dec)),
    ?assertEqual(<<"s3cret">>, maps:get(password, Dec)),
    ?assertEqual(<<"192.0.2.10">>, maps:get(peerhost, Dec)),
    %% Anonymous plus peer address decodes without credentials.
    Anon = indra_brokerlink:encode_bind_meta(<<"dev-a">>, false, 30,
                                            {undefined, undefined},
                                            <<"2001:db8::1">>),
    {ok, ADec} = indra_brokerlink:decode_bind_meta(Anon),
    ?assertEqual(undefined, maps:get(username, ADec)),
    ?assertEqual(undefined, maps:get(password, ADec)),
    ?assertEqual(<<"2001:db8::1">>, maps:get(peerhost, ADec)),
    %% Legacy binds decode with no peer address.
    {ok, LDec} = indra_brokerlink:decode_bind_meta(
                   indra_brokerlink:encode_bind_meta(<<"dev-l">>, true, 60)),
    ?assertEqual(undefined, maps:get(peerhost, LDec)),
    %% Undefined peer encodes exactly like /4.
    ?assertEqual(indra_brokerlink:encode_bind_meta(<<"dev-1">>, true, 60,
                                                  {<<"alice">>, <<"s3cret">>}),
                 indra_brokerlink:encode_bind_meta(<<"dev-1">>, true, 60,
                                                  {<<"alice">>, <<"s3cret">>},
                                                  undefined)),
    %% A non-IP peer literal is rejected at encode time.
    ?assertError(badarg,
                 indra_brokerlink:encode_bind_meta(<<"d">>, true, 60,
                                                  {undefined, undefined},
                                                  <<"not-an-ip">>)),
    %% A trailing section that is neither credentials nor a peer
    %% address stays malformed: valid credentials followed by a
    %% non-IP peer section.
    ?assertEqual({error, malformed_bind_meta},
                 indra_brokerlink:decode_bind_meta(
                   <<0, 5, "dev-1", 1, 0, 60, 0, 5, "alice",
                     0, 6, "s3cret", 0, 2, "zz">>)).

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
%% Topic-alias metadata contracts (B4-05)
%%====================================================================

bind_meta_alias_roundtrip_test() ->
    %% The /6 form appends the client's receive limit; the kernel
    %% outbound table is bounded by it.
    Meta = indra_brokerlink:encode_bind_meta(<<"dev-1">>, true, 60,
                                            {undefined, undefined},
                                            undefined, 10),
    {ok, Dec} = indra_brokerlink:decode_bind_meta(Meta),
    ?assertEqual(<<"dev-1">>, maps:get(client_id, Dec)),
    ?assertEqual(10, maps:get(client_alias_max, Dec)),
    ?assertEqual(undefined, maps:get(peerhost, Dec)),
    %% With credentials and a peer address the alias still trails last.
    Full = indra_brokerlink:encode_bind_meta(<<"dev-1">>, true, 60,
                                            {<<"alice">>, <<"s3cret">>},
                                            <<"192.0.2.10">>, 7),
    {ok, FDec} = indra_brokerlink:decode_bind_meta(Full),
    ?assertEqual(<<"alice">>, maps:get(username, FDec)),
    ?assertEqual(<<"192.0.2.10">>, maps:get(peerhost, FDec)),
    ?assertEqual(7, maps:get(client_alias_max, FDec)),
    %% Legacy binds without the section decode with maximum 0.
    {ok, LDec} = indra_brokerlink:decode_bind_meta(
                   indra_brokerlink:encode_bind_meta(<<"dev-l">>, true, 60)),
    ?assertEqual(0, maps:get(client_alias_max, LDec)).

bind_meta_alias_peer_variants_test() ->
    %% Every bind variant with and without the peer section, including
    %% with the B4-05 alias section present (FX-01: the edge always sends
    %% /6, so the kernel must see the peer on alias-carrying binds).
    %% /3 anonymous, no peer, no alias.
    {ok, D3} = indra_brokerlink:decode_bind_meta(
                 indra_brokerlink:encode_bind_meta(<<"v3">>, true, 60)),
    ?assertEqual(undefined, maps:get(peerhost, D3)),
    ?assertEqual(0, maps:get(client_alias_max, D3)),
    %% /4 credentials, no peer, no alias.
    {ok, D4} = indra_brokerlink:decode_bind_meta(
                 indra_brokerlink:encode_bind_meta(<<"v4">>, true, 60,
                                                  {<<"u">>, <<"p">>})),
    ?assertEqual(<<"u">>, maps:get(username, D4)),
    ?assertEqual(undefined, maps:get(peerhost, D4)),
    ?assertEqual(0, maps:get(client_alias_max, D4)),
    %% /5 anonymous plus peer, no alias.
    {ok, D5a} = indra_brokerlink:decode_bind_meta(
                  indra_brokerlink:encode_bind_meta(<<"v5a">>, true, 60,
                                                   {undefined, undefined},
                                                   <<"127.0.0.1">>)),
    ?assertEqual(<<"127.0.0.1">>, maps:get(peerhost, D5a)),
    ?assertEqual(0, maps:get(client_alias_max, D5a)),
    %% /5 credentials plus peer, no alias.
    {ok, D5c} = indra_brokerlink:decode_bind_meta(
                  indra_brokerlink:encode_bind_meta(<<"v5c">>, true, 60,
                                                   {<<"u">>, <<"p">>},
                                                   <<"192.0.2.10">>)),
    ?assertEqual(<<"192.0.2.10">>, maps:get(peerhost, D5c)),
    %% /6 anonymous, no peer, with alias.
    {ok, D6a} = indra_brokerlink:decode_bind_meta(
                  indra_brokerlink:encode_bind_meta(<<"v6a">>, true, 60,
                                                   {undefined, undefined},
                                                   undefined, 10)),
    ?assertEqual(undefined, maps:get(peerhost, D6a)),
    ?assertEqual(10, maps:get(client_alias_max, D6a)),
    %% /6 credentials, no peer, with alias.
    {ok, D6c} = indra_brokerlink:decode_bind_meta(
                  indra_brokerlink:encode_bind_meta(<<"v6c">>, true, 60,
                                                   {<<"u">>, <<"p">>},
                                                   undefined, 10)),
    ?assertEqual(undefined, maps:get(peerhost, D6c)),
    ?assertEqual(10, maps:get(client_alias_max, D6c)),
    %% FX-01 regression: anonymous plus peer plus alias 0 (what a 3.1.1
    %% edge always sends) must keep the peer, never decode it as a
    %% username with an empty password.
    {ok, D6ap0} = indra_brokerlink:decode_bind_meta(
                    indra_brokerlink:encode_bind_meta(<<"v6ap0">>, true, 60,
                                                     {undefined, undefined},
                                                     <<"127.0.0.1">>, 0)),
    ?assertEqual(undefined, maps:get(username, D6ap0)),
    ?assertEqual(<<"127.0.0.1">>, maps:get(peerhost, D6ap0)),
    ?assertEqual(0, maps:get(client_alias_max, D6ap0)),
    %% Anonymous plus peer plus nonzero alias.
    {ok, D6ap} = indra_brokerlink:decode_bind_meta(
                   indra_brokerlink:encode_bind_meta(<<"v6ap">>, false, 30,
                                                    {undefined, undefined},
                                                    <<"2001:db8::1">>, 9)),
    ?assertEqual(<<"2001:db8::1">>, maps:get(peerhost, D6ap)),
    ?assertEqual(9, maps:get(client_alias_max, D6ap)),
    %% Credentials plus peer plus alias 0 and nonzero.
    {ok, D6cp0} = indra_brokerlink:decode_bind_meta(
                    indra_brokerlink:encode_bind_meta(<<"v6cp0">>, true, 60,
                                                     {<<"u">>, <<"p">>},
                                                     <<"192.0.2.10">>, 0)),
    ?assertEqual(<<"u">>, maps:get(username, D6cp0)),
    ?assertEqual(<<"192.0.2.10">>, maps:get(peerhost, D6cp0)),
    ?assertEqual(0, maps:get(client_alias_max, D6cp0)),
    {ok, D6cp} = indra_brokerlink:decode_bind_meta(
                   indra_brokerlink:encode_bind_meta(<<"v6cp">>, true, 60,
                                                    {<<"u">>, <<"p">>},
                                                    <<"192.0.2.10">>, 7)),
    ?assertEqual(<<"192.0.2.10">>, maps:get(peerhost, D6cp)),
    ?assertEqual(7, maps:get(client_alias_max, D6cp)),
    %% /7 will variants keep the peer with the alias present.
    Will = #{topic => <<"will/test">>, payload => <<"bye">>,
             qos => 0, retain => false},
    {ok, D7a} = indra_brokerlink:decode_bind_meta(
                  indra_brokerlink:encode_bind_meta(<<"v7a">>, true, 5,
                                                   {undefined, undefined},
                                                   <<"127.0.0.1">>, 0, Will)),
    ?assertEqual(<<"127.0.0.1">>, maps:get(peerhost, D7a)),
    ?assertEqual(0, maps:get(client_alias_max, D7a)),
    ?assertEqual(<<"will/test">>, maps:get(will_topic, D7a)),
    {ok, D7c} = indra_brokerlink:decode_bind_meta(
                  indra_brokerlink:encode_bind_meta(<<"v7c">>, false, 60,
                                                   {<<"u">>, <<"p">>},
                                                   <<"192.0.2.10">>, 7, Will)),
    ?assertEqual(<<"u">>, maps:get(username, D7c)),
    ?assertEqual(<<"192.0.2.10">>, maps:get(peerhost, D7c)),
    ?assertEqual(7, maps:get(client_alias_max, D7c)),
    %% A bind without the peer section still decodes with the peer unset.
    {ok, DNoPeer} = indra_brokerlink:decode_bind_meta(
                      indra_brokerlink:encode_bind_meta(<<"vnp">>, true, 60,
                                                       {<<"u">>, <<"p">>},
                                                       undefined, 0)),
    ?assertEqual(undefined, maps:get(peerhost, DNoPeer)).

%%====================================================================
%% Last-will bind section (F1-01)
%%====================================================================

bind_meta_will_roundtrip_test() ->
    Will = #{topic => <<"will/test">>, payload => <<"client-gone">>,
             qos => 0, retain => false},
    Meta = indra_brokerlink:encode_bind_meta(<<"dev-w">>, true, 5,
                                            {undefined, undefined},
                                            undefined, 0, Will),
    {ok, Dec} = indra_brokerlink:decode_bind_meta(Meta),
    ?assertEqual(<<"dev-w">>, maps:get(client_id, Dec)),
    ?assertEqual(true, maps:get(clean_start, Dec)),
    ?assertEqual(5, maps:get(keepalive, Dec)),
    ?assertEqual(<<"will/test">>, maps:get(will_topic, Dec)),
    ?assertEqual(<<"client-gone">>, maps:get(will_payload, Dec)),
    ?assertEqual(0, maps:get(will_qos, Dec)),
    ?assertEqual(false, maps:get(will_retain, Dec)),
    %% With credentials, peer and alias the will still rides first.
    Full = indra_brokerlink:encode_bind_meta(<<"dev-w">>, false, 60,
                                            {<<"alice">>, <<"s3cret">>},
                                            <<"192.0.2.10">>, 7, Will),
    {ok, FDec} = indra_brokerlink:decode_bind_meta(Full),
    ?assertEqual(<<"alice">>, maps:get(username, FDec)),
    ?assertEqual(<<"192.0.2.10">>, maps:get(peerhost, FDec)),
    ?assertEqual(7, maps:get(client_alias_max, FDec)),
    ?assertEqual(<<"will/test">>, maps:get(will_topic, FDec)),
    %% No-will binds decode with undefined will strings, and the /7
    %% encoding without a will is exactly the /6 encoding.
    Legacy = indra_brokerlink:encode_bind_meta(<<"dev-w">>, true, 5,
                                              {undefined, undefined},
                                              undefined),
    ?assertEqual(indra_brokerlink:encode_bind_meta(<<"dev-w">>, true, 5,
                                                  {undefined, undefined},
                                                  undefined, 0),
                 indra_brokerlink:encode_bind_meta(<<"dev-w">>, true, 5,
                                                  {undefined, undefined},
                                                  undefined, 0, undefined)),
    {ok, LDec} = indra_brokerlink:decode_bind_meta(Legacy),
    ?assertEqual(undefined, maps:get(will_topic, LDec)),
    ?assertEqual(undefined, maps:get(will_payload, LDec)),
    %% Empty will topic rejected at encode time (fail closed).
    ?assertError(badarg,
                 indra_brokerlink:encode_bind_meta(<<"d">>, true, 5,
                                                  {undefined, undefined},
                                                  undefined, 0,
                                                  #{topic => <<>>,
                                                    payload => <<"x">>,
                                                    qos => 0,
                                                    retain => false})).

disconnect_meta_roundtrip_test() ->
    Meta = indra_brokerlink:encode_disconnect_meta(<<"dev-9">>),
    ?assertEqual({ok, #{client_id => <<"dev-9">>}},
                 indra_brokerlink:decode_disconnect_meta(Meta)),
    ?assertEqual({error, malformed_unbind_meta},
                 indra_brokerlink:decode_disconnect_meta(<<0, 4, "ab">>)).

session_binding_alias_roundtrip_test() ->
    %% The /4 form carries the kernel inbound bound for CONNACK
    %% negotiation; the /3 form decodes with maximum 0.
    Meta = indra_brokerlink:encode_session_binding_meta(99, true, 0, 10),
    ?assertEqual(12, byte_size(Meta)),
    {ok, Dec} = indra_brokerlink:decode_session_binding_meta(Meta),
    ?assertEqual(99, maps:get(session_id, Dec)),
    ?assertEqual(true, maps:get(session_present, Dec)),
    ?assertEqual(0, maps:get(return_code, Dec)),
    ?assertEqual(10, maps:get(alias_max, Dec)),
    Legacy = indra_brokerlink:encode_session_binding_meta(99, false, 2),
    {ok, LDec} = indra_brokerlink:decode_session_binding_meta(Legacy),
    ?assertEqual(0, maps:get(alias_max, LDec)).

publish_meta_alias_roundtrip_test() ->
    %% The /6 form appends the alias; the /5 form decodes with alias 0.
    Meta = indra_brokerlink:encode_publish_meta(<<"sport/tennis">>, 42, 1, true, false, 3),
    {ok, Dec} = indra_brokerlink:decode_publish_meta(Meta),
    ?assertEqual(<<"sport/tennis">>, maps:get(topic, Dec)),
    ?assertEqual(42, maps:get(packet_id, Dec)),
    ?assertEqual(3, maps:get(alias, Dec)),
    %% Alias-by-reference: an empty topic with a nonzero alias decodes.
    Ref = indra_brokerlink:encode_publish_meta(<<>>, 0, 0, false, false, 3),
    {ok, RDec} = indra_brokerlink:decode_publish_meta(Ref),
    ?assertEqual(<<>>, maps:get(topic, RDec)),
    ?assertEqual(3, maps:get(alias, RDec)),
    %% Legacy metas without the section decode with alias 0.
    {ok, LDec} = indra_brokerlink:decode_publish_meta(
                   indra_brokerlink:encode_publish_meta(<<"t">>, 0, 0, false, false)),
    ?assertEqual(0, maps:get(alias, LDec)),
    %% An empty topic without an alias stays malformed, and an empty
    %% topic is rejected at encode time without one.
    ?assertEqual({error, malformed_publish_meta},
                 indra_brokerlink:decode_publish_meta(<<0, 0, 0, 0, 0, 0, 0>>)),
    ?assertError(badarg,
                 indra_brokerlink:encode_publish_meta(<<>>, 0, 0, false, false)).

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

inbound_frames_leave_no_retained_state_test() ->
    %% Every inbound kernel frame used to be prepended to a `frames'
    %% list in the shard server state that was never read or trimmed,
    %% so shard memory grew monotonically for the life of the edge
    %% (process memory that never drains after load stops). The shard
    %% must retain no per-frame state once a frame is dispatched.
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Server = spawn(fun() -> dispatch_server(LSock) end),
    {ok, Registry} = indra_conn_registry:start_link(),
    {ok, Client} = indra_brokerlink:start_link([{transport, tcp},
                                                {host, "127.0.0.1"},
                                                {port, Port}]),
    try
        ok = indra_conn_registry:register(7701, self()),
        %% Stays below the Q3 per-connection dispatch bound (128
        %% frames): past it QoS 0 is shed by design and counted, so a
        %% burst larger than the cap cannot expect 1:1 delivery here.
        %% The guard below is structural (no retained keys, empty
        %% buffer and mailbox) and holds at any N.
        N = 100,
        Meta = indra_brokerlink:encode_publish_meta(<<"t">>, 0, 0, false, false),
        Frame = indra_brokerlink:encode_frame(16#0021, 7701, 9, Meta, <<"hi">>),
        lists:foreach(fun(_) -> Server ! {emit, Frame} end, lists:seq(1, N)),
        receive_n_broker_frames(N),
        %% Drain period: dispatched frames must not linger in the
        %% shard server state, mailbox, or reassembly buffer.
        timer:sleep(500),
        State = sys:get_state(Client),
        ?assertEqual(false, maps:is_key(frames, State)),
        ?assertEqual(false, maps:is_key(last_pong, State)),
        ?assertEqual(<<>>, maps:get(buffer, State)),
        {message_queue_len, MQLen} = process_info(Client, message_queue_len),
        ?assertEqual(0, MQLen)
    after
        catch indra_edge_counters:credit_delete(7701),
        indra_brokerlink:stop(Client),
        indra_conn_registry:stop(Registry),
        gen_tcp:close(LSock)
    end.

%% @private Receive exactly N forwarded inbound frames.
receive_n_broker_frames(0) -> ok;
receive_n_broker_frames(N) ->
    receive
        {'$gen_cast', {broker_frame, _, _, _}} ->
            receive_n_broker_frames(N - 1)
    after 10000 ->
        error({broker_frame_timeout, N})
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

%%====================================================================
%% Sprint 11 restart immunity
%%====================================================================

reconnect_recovers_after_core_restart_test() ->
    %% Fake core on an ephemeral port; the client reconnects with fast
    %% backoff after we kill and re-listen.
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Parent = self(),
    Core1 = spawn(fun() -> accept_and_forward(LSock, Parent) end),
    {ok, Registry} = indra_conn_registry:start_link(),
    {ok, Pid} = indra_brokerlink:start_link([{transport, tcp},
                                             {host, "127.0.0.1"},
                                             {port, Port},
                                             {reconnect, true},
                                             {backoff_base_ms, 20},
                                             {backoff_max_ms, 100}]),
    try
        %% Baseline ping works.
        ?assertEqual(ok, indra_brokerlink:ping(Pid, 6101)),
        receive {got_frame, _} -> ok after 5000 -> error(first_ping_timeout) end,
        %% Kill the core: close accepted socket (via the acceptor) and
        %% the listen socket so reconnects fail during the outage.
        exit(Core1, kill),
        ok = gen_tcp:close(LSock),
        %% Sends now fail fast instead of hanging.
        ?assertEqual({error, not_connected}, wait_send_down(Pid)),
        %% Restart the core on the same port and serve again.
        {ok, LSock2} = relisten(Port, 50),
        _Core2 = spawn(fun() -> accept_and_forward(LSock2, Parent) end),
        %% Reconnect heals without any client restart: ping flows again.
        ?assertEqual(ok, wait_ping_up(Pid, 40)),
        receive {got_frame, _} -> ok after 5000 -> error(reconnect_ping_timeout) end,
        gen_tcp:close(LSock2)
    after
        indra_brokerlink:stop(Pid),
        indra_conn_registry:stop(Registry),
        catch gen_tcp:close(LSock)
    end.

%% @private Wait until ping reports steady not-connected (core down).
%% Any other error (e.g. transient einval while the close is being
%% processed) just means "not yet settled": keep polling.
wait_send_down(_Pid, 0) ->
    error(core_never_dropped);
wait_send_down(Pid, Tries) ->
    case indra_brokerlink:ping(Pid, 6101) of
        {error, not_connected} -> {error, not_connected};
        _ -> timer:sleep(50), wait_send_down(Pid, Tries - 1)
    end.

wait_send_down(Pid) ->
    wait_send_down(Pid, 60).

%% @private Wait until ping succeeds again (reconnected).
wait_ping_up(_Pid, 0) ->
    error(reconnect_timeout);
wait_ping_up(Pid, Tries) ->
    case indra_brokerlink:ping(Pid, 6101) of
        ok -> ok;
        {error, _} -> timer:sleep(50), wait_ping_up(Pid, Tries - 1)
    end.

%% @private Re-listen a fixed port, retrying against TIME_WAIT churn.
relisten(_Port, 0) ->
    error(relisten_timeout);
relisten(Port, Tries) ->
    case gen_tcp:listen(Port, [binary, {packet, raw},
                               {active, false}, {reuseaddr, true}]) of
        {ok, LSock} -> {ok, LSock};
        {error, _} -> timer:sleep(100), relisten(Port, Tries - 1)
    end.
