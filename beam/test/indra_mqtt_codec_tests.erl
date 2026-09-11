%% @doc EUnit tests for {@link indra_mqtt_codec}.
-module(indra_mqtt_codec_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Valid packets
%%====================================================================

pingreq_test() ->
    {ok, Pkt, Rest} = indra_mqtt_codec:decode_packet(<<16#C0, 16#00>>),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(12, maps:get(type, Pkt)),
    ?assertEqual(pingreq, maps:get(type_atom, Pkt)),
    ?assertEqual(0, maps:get(flags, Pkt)),
    ?assertEqual(0, maps:get(remaining_length, Pkt)),
    ?assertEqual(<<>>, maps:get(payload, Pkt)).

pingresp_test() ->
    {ok, Pkt, Rest} = indra_mqtt_codec:decode_packet(<<16#D0, 16#00>>),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(13, maps:get(type, Pkt)),
    ?assertEqual(pingresp, maps:get(type_atom, Pkt)),
    ?assertEqual(0, maps:get(flags, Pkt)),
    ?assertEqual(0, maps:get(remaining_length, Pkt)),
    ?assertEqual(<<>>, maps:get(payload, Pkt)).

disconnect_test() ->
    {ok, Pkt, Rest} = indra_mqtt_codec:decode_packet(<<16#E0, 16#00>>),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(14, maps:get(type, Pkt)),
    ?assertEqual(disconnect, maps:get(type_atom, Pkt)),
    ?assertEqual(0, maps:get(flags, Pkt)),
    ?assertEqual(0, maps:get(remaining_length, Pkt)),
    ?assertEqual(<<>>, maps:get(payload, Pkt)).

puback_test() ->
    {ok, Pkt, Rest} = indra_mqtt_codec:decode_packet(<<16#40, 16#02, 16#00, 16#0A>>),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(4, maps:get(type, Pkt)),
    ?assertEqual(puback, maps:get(type_atom, Pkt)),
    ?assertEqual(0, maps:get(flags, Pkt)),
    ?assertEqual(2, maps:get(remaining_length, Pkt)),
    ?assertEqual(<<16#00, 16#0A>>, maps:get(payload, Pkt)).

connect_minimal_test() ->
    Payload = binary:copy(<<0>>, 10),
    Bin = <<16#10, 10, Payload/binary>>,
    {ok, Pkt, Rest} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(1, maps:get(type, Pkt)),
    ?assertEqual(connect, maps:get(type_atom, Pkt)),
    ?assertEqual(0, maps:get(flags, Pkt)),
    ?assertEqual(10, maps:get(remaining_length, Pkt)),
    ?assertEqual(Payload, maps:get(payload, Pkt)).

publish_qos0_test() ->
    %% Topic "t", payload "hi": variable header <<0,1,"t">> (3) + "hi" (2) = 5.
    Body = <<0, 1, $t, $h, $i>>,
    {ok, Pkt, Rest} = indra_mqtt_codec:decode_packet(<<16#30, 5, Body/binary>>),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(3, maps:get(type, Pkt)),
    ?assertEqual(publish, maps:get(type_atom, Pkt)),
    ?assertEqual(0, maps:get(flags, Pkt)),
    ?assertEqual(5, maps:get(remaining_length, Pkt)),
    ?assertEqual(Body, maps:get(payload, Pkt)).

publish_qos1_with_packet_id_test() ->
    %% Flags 0010 (QoS 1), topic "ab", packet id 16, payload "Z".
    Body = <<0, 2, $a, $b, 0, 16, $Z>>,
    {ok, Pkt, Rest} = indra_mqtt_codec:decode_packet(<<16#32, 7, Body/binary>>),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(3, maps:get(type, Pkt)),
    ?assertEqual(2, maps:get(flags, Pkt)),
    ?assertEqual(7, maps:get(remaining_length, Pkt)),
    ?assertEqual(Body, maps:get(payload, Pkt)).

publish_qos1_dup_retain_flags_test() ->
    %% Flags 1011: DUP=1, QoS=1, RETAIN=1.
    Body = <<0, 1, $t, 0, 1, $x>>,
    {ok, Pkt, _} = indra_mqtt_codec:decode_packet(<<16#3B, 6, Body/binary>>),
    ?assertEqual(3, maps:get(type, Pkt)),
    ?assertEqual(16#0B, maps:get(flags, Pkt)).

multibyte_remaining_length_test() ->
    %% Remaining length 321 encodes as C1 02.
    ?assertEqual(<<16#C1, 16#02>>, indra_mqtt_codec:encode_remaining_length(321)),
    Body = binary:copy(<<$a>>, 321),
    Bin = <<16#30, 16#C1, 16#02, Body/binary>>,
    {ok, Pkt, Rest} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(321, maps:get(remaining_length, Pkt)),
    ?assertEqual(Body, maps:get(payload, Pkt)).

remaining_length_codec_roundtrip_test() ->
    lists:foreach(
      fun(N) ->
          Enc = indra_mqtt_codec:encode_remaining_length(N),
          {ok, N, Len} = indra_mqtt_codec:decode_remaining_length(Enc),
          ?assertEqual(byte_size(Enc), Len)
      end, [0, 1, 127, 128, 129, 321, 16383, 16384, 2097151, 2097152, 268435455]).

remaining_length_known_vectors_test() ->
    ?assertEqual(<<0>>, indra_mqtt_codec:encode_remaining_length(0)),
    ?assertEqual(<<127>>, indra_mqtt_codec:encode_remaining_length(127)),
    ?assertEqual(<<16#80, 16#01>>, indra_mqtt_codec:encode_remaining_length(128)),
    ?assertEqual(<<16#FF, 16#7F>>, indra_mqtt_codec:encode_remaining_length(16383)),
    ?assertEqual(<<16#80, 16#80, 16#01>>, indra_mqtt_codec:encode_remaining_length(16384)),
    ?assertEqual(<<16#FF, 16#FF, 16#7F>>, indra_mqtt_codec:encode_remaining_length(2097151)),
    ?assertEqual(<<16#80, 16#80, 16#80, 16#01>>, indra_mqtt_codec:encode_remaining_length(2097152)),
    ?assertEqual(<<16#FF, 16#FF, 16#FF, 16#7F>>,
                 indra_mqtt_codec:encode_remaining_length(268435455)).

concatenated_packets_test() ->
    Both = <<16#C0, 16#00, 16#D0, 16#00>>,
    {ok, First, Rest} = indra_mqtt_codec:decode_packet(Both),
    ?assertEqual(pingreq, maps:get(type_atom, First)),
    {ok, Second, Rest2} = indra_mqtt_codec:decode_packet(Rest),
    ?assertEqual(pingresp, maps:get(type_atom, Second)),
    ?assertEqual(<<>>, Rest2).

trailing_bytes_preserved_test() ->
    Bin = <<16#C0, 16#00, 16#FF>>,
    {ok, Pkt, Rest} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(pingreq, maps:get(type_atom, Pkt)),
    ?assertEqual(<<16#FF>>, Rest).

%%====================================================================
%% Fragmentation (streaming)
%%====================================================================

empty_needs_more_test() ->
    ?assertEqual({more, 1}, indra_mqtt_codec:decode_packet(<<>>)).

single_fixed_header_byte_needs_more_test() ->
    ?assertEqual({more, 1}, indra_mqtt_codec:decode_packet(<<16#C0>>)).

truncated_remaining_length_needs_more_test() ->
    %% 0x80 has the continuation bit set but no following byte yet.
    ?assertEqual({more, 1}, indra_mqtt_codec:decode_packet(<<16#10, 16#80>>)),
    ?assertEqual({more, 1}, indra_mqtt_codec:decode_packet(<<16#30, 16#80>>)).

incomplete_payload_needs_more_test() ->
    %% PUBLISH claims 5 payload bytes, only 2 present.
    ?assertEqual({more, 3},
                 indra_mqtt_codec:decode_packet(<<16#30, 5, $a, $b>>)).

%%====================================================================
%% Malformed input rejection
%%====================================================================

five_byte_remaining_length_rejected_test() ->
    %% Fourth byte still has the continuation bit set: malformed.
    ?assertEqual({error, malformed_remaining_length},
                 indra_mqtt_codec:decode_packet(
                   <<16#30, 16#FF, 16#FF, 16#FF, 16#80, 16#00>>)).

invalid_packet_types_rejected_test() ->
    ?assertEqual({error, {invalid_packet_type, 0}},
                 indra_mqtt_codec:decode_packet(<<16#00, 16#00>>)),
    ?assertEqual({error, {invalid_packet_type, 15}},
                 indra_mqtt_codec:decode_packet(<<16#F0, 16#00>>)).

nonzero_pingreq_flags_rejected_test() ->
    ?assertEqual({error, {invalid_flags, pingreq, 1}},
                 indra_mqtt_codec:decode_packet(<<16#C1, 16#00>>)).

nonzero_pingresp_flags_rejected_test() ->
    ?assertEqual({error, {invalid_flags, pingresp, 2}},
                 indra_mqtt_codec:decode_packet(<<16#D2, 16#00>>)).

nonzero_puback_flags_rejected_test() ->
    ?assertEqual({error, {invalid_flags, puback, 1}},
                 indra_mqtt_codec:decode_packet(<<16#41, 16#02, 16#00, 16#01>>)).

nonzero_connect_flags_rejected_test() ->
    ?assertEqual({error, {invalid_flags, connect, 7}},
                 indra_mqtt_codec:decode_packet(<<16#17, 16#00>>)).

nonzero_disconnect_flags_rejected_test() ->
    ?assertEqual({error, {invalid_flags, disconnect, 4}},
                 indra_mqtt_codec:decode_packet(<<16#E4, 16#00>>)).

publish_qos3_rejected_test() ->
    %% Flags 0110: QoS bits = 11 (3), forbidden by MQTT 3.1.1 §3.3.1.2.
    ?assertEqual({error, {invalid_flags, publish, 6}},
                 indra_mqtt_codec:decode_packet(<<16#36, 16#00>>)).

packet_type_mapping_helpers_test() ->
    ?assertEqual(connect, indra_mqtt_codec:packet_type_atom(1)),
    ?assertEqual(publish, indra_mqtt_codec:packet_type_atom(3)),
    ?assertEqual(puback, indra_mqtt_codec:packet_type_atom(4)),
    ?assertEqual(pingreq, indra_mqtt_codec:packet_type_atom(12)),
    ?assertEqual(pingresp, indra_mqtt_codec:packet_type_atom(13)),
    ?assertEqual(disconnect, indra_mqtt_codec:packet_type_atom(14)),
    ?assertEqual(1, indra_mqtt_codec:packet_type_code(connect)),
    ?assertEqual(3, indra_mqtt_codec:packet_type_code(publish)),
    ?assertEqual(12, indra_mqtt_codec:packet_type_code(pingreq)),
    ?assertEqual(14, indra_mqtt_codec:packet_type_code(disconnect)).

%%====================================================================
%% CONNECT decoding (Sprint 2 handshake)
%%====================================================================

decode_connect_minimal_clean_test() ->
    {ok, Pkt, _} = indra_mqtt_codec:decode_packet(connect_bytes(<<"s-1">>, 16#02, 60)),
    ?assertEqual(connect, maps:get(type_atom, Pkt)),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(<<"MQTT">>, maps:get(protocol_name, Conn)),
    ?assertEqual(4, maps:get(protocol_level, Conn)),
    ?assertEqual(true, maps:get(clean_start, Conn)),
    ?assertEqual(60, maps:get(keepalive, Conn)),
    ?assertEqual(<<"s-1">>, maps:get(client_id, Conn)),
    ?assertEqual(false, maps:get(username_flag, Conn)),
    ?assertEqual(false, maps:get(will_flag, Conn)).

decode_connect_persistent_with_auth_and_will_test() ->    %% Flags C0 (username+password) | 04 (will) | 0C (will QoS 1): 0xCC.
    Var = <<0, 4, "MQTT", 4, 16#CC, 0, 10>>,
    Payload = [<<0, 3, "cid">>,
               <<0, 2, "wt">>, <<0, 2, "wm">>,
               <<0, 1, "u">>, <<0, 1, "p">>],
    Body = iolist_to_binary([Var | Payload]),
    Bin = <<16#10, (byte_size(Body)), Body/binary>>,
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(false, maps:get(clean_start, Conn)),
    ?assertEqual(<<"cid">>, maps:get(client_id, Conn)),
    ?assertEqual(true, maps:get(username_flag, Conn)),
    ?assertEqual(true, maps:get(password_flag, Conn)),
    ?assertEqual(true, maps:get(will_flag, Conn)),
    ?assertEqual(1, maps:get(will_qos, Conn)),
    ?assertEqual(false, maps:get(will_retain, Conn)).

decode_connect_captures_username_password_test() ->
    %% Flags C0 (username+password) | 02 (clean): 0xC2.
    Var = <<0, 4, "MQTT", 4, 16#C2, 0, 60>>,
    Body = <<Var/binary, 0, 3, "cid", 0, 5, "alice", 0, 6, "s3cret">>,
    Bin = <<16#10, (byte_size(Body)), Body/binary>>,
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(true, maps:get(username_flag, Conn)),
    ?assertEqual(true, maps:get(password_flag, Conn)),
    ?assertEqual(<<"alice">>, maps:get(username, Conn)),
    ?assertEqual(<<"s3cret">>, maps:get(password, Conn)).

decode_connect_anonymous_has_no_credentials_test() ->
    {ok, Pkt, _} = indra_mqtt_codec:decode_packet(connect_bytes(<<"s-1">>, 16#02, 60)),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(undefined, maps:get(username, Conn)),
    ?assertEqual(undefined, maps:get(password, Conn)).

decode_connect_unsupported_protocol_test() ->
    %% Level 5 (MQTT 5.0) is outside the 3.1.1 edge scope.
    Var = <<0, 4, "MQTT", 5, 16#02, 0, 60>>,
    Body = <<Var/binary, 0, 1, "a">>,
    ?assertEqual({error, {unsupported_protocol, <<"MQTT">>, 5}},
                 indra_mqtt_codec:decode_connect(Body)),
    %% Legacy MQIsdp name rejected as well.
    Var3 = <<0, 6, "MQIsdp", 3, 16#02, 0, 60>>,
    Body3 = <<Var3/binary, 0, 1, "a">>,
    ?assertEqual({error, {unsupported_protocol, <<"MQIsdp">>, 3}},
                 indra_mqtt_codec:decode_connect(Body3)).

decode_connect_reserved_flag_rejected_test() ->
    ?assertEqual({error, {invalid_connect_flags, 16#03}},
                 indra_mqtt_codec:decode_connect(connect_body(<<"a">>, 16#03, 60))).

decode_connect_will_qos3_rejected_test() ->
    %% Flags 04 (will) | 18 (QoS 3): forbidden.
    ?assertEqual({error, {invalid_connect_flags, 16#1C}},
                 indra_mqtt_codec:decode_connect(connect_body(<<"a">>, 16#1C, 60))).

decode_connect_password_without_username_rejected_test() ->
    ?assertEqual({error, {invalid_connect_flags, 16#42}},
                 indra_mqtt_codec:decode_connect(connect_body(<<"a">>, 16#42, 60))).

decode_connect_truncated_test() ->
    ?assertEqual({error, truncated_connect},
                 indra_mqtt_codec:decode_connect(<<0, 4, "MQ">>)),
    ?assertEqual({error, truncated_connect},
                 indra_mqtt_codec:decode_connect(<<>>)),
    %% Declared client id longer than the bytes present.
    Var = <<0, 4, "MQTT", 4, 16#02, 0, 60>>,
    ?assertEqual({error, truncated_connect},
                 indra_mqtt_codec:decode_connect(<<Var/binary, 0, 9, "short">>)).

decode_connect_trailing_garbage_rejected_test() ->
    Var = <<0, 4, "MQTT", 4, 16#02, 0, 60>>,
    ?assertEqual({error, trailing_connect_bytes},
                 indra_mqtt_codec:decode_connect(<<Var/binary, 0, 1, "a", 16#FF>>)).

%%====================================================================
%% CONNACK encoding
%%====================================================================

encode_connack_vectors_test() ->
    ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>,
                 indra_mqtt_codec:encode_connack(false, 0)),
    ?assertEqual(<<16#20, 16#02, 16#01, 16#00>>,
                 indra_mqtt_codec:encode_connack(true, 0)),
    ?assertEqual(<<16#20, 16#02, 16#00, 16#04>>,
                 indra_mqtt_codec:encode_connack(false, 4)),
    ?assertEqual(<<16#20, 16#02, 16#01, 16#02>>,
                 indra_mqtt_codec:encode_connack(true, 2)).

%%====================================================================
%% Helpers
%%====================================================================

connect_body(ClientId, Flags, Keepalive) ->
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    <<Var/binary, (byte_size(ClientId)):16/big, ClientId/binary>>.

connect_bytes(ClientId, Flags, Keepalive) ->
    Body = connect_body(ClientId, Flags, Keepalive),
    <<16#10, (byte_size(Body)), Body/binary>>.

%%====================================================================
%% SUBSCRIBE / SUBACK (Sprint 3 messaging loop)
%%====================================================================

decode_subscribe_single_test() ->
    %% Packet id 7, one filter "sport/tennis" QoS 1.
    Body = <<0, 7, 0, 12, "sport/tennis", 1>>,
    Bin = <<16#82, (byte_size(Body)), Body/binary>>,
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(subscribe, maps:get(type_atom, Pkt)),
    {ok, Sub} = indra_mqtt_codec:decode_subscribe(maps:get(payload, Pkt)),
    ?assertEqual(7, maps:get(packet_id, Sub)),
    ?assertEqual([{<<"sport/tennis">>, 1}], maps:get(subscriptions, Sub)).

decode_subscribe_multi_test() ->
    Body = <<0, 9, 0, 1, "a", 0, 0, 5, "sport", 2>>,
    Bin = <<16#82, (byte_size(Body)), Body/binary>>,
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    {ok, Sub} = indra_mqtt_codec:decode_subscribe(maps:get(payload, Pkt)),
    ?assertEqual(9, maps:get(packet_id, Sub)),
    ?assertEqual([{<<"a">>, 0}, {<<"sport">>, 2}], maps:get(subscriptions, Sub)).

decode_subscribe_rejects_test() ->
    %% Zero packet id.
    ?assertEqual({error, malformed_subscribe},
                 indra_mqtt_codec:decode_subscribe(<<0, 0, 0, 1, "a", 0>>)),
    %% Empty filter list.
    ?assertEqual({error, empty_subscribe},
                 indra_mqtt_codec:decode_subscribe(<<0, 7>>)),
    %% Requested QoS 3.
    ?assertEqual({error, {invalid_subscribe_qos, 3}},
                 indra_mqtt_codec:decode_subscribe(<<0, 7, 0, 1, "a", 3>>)),
    %% Truncated filter bytes.
    ?assertEqual({error, truncated_subscribe},
                 indra_mqtt_codec:decode_subscribe(<<0, 7, 0, 9, "short">>)),
    %% Empty filter string.
    ?assertEqual({error, malformed_subscribe},
                 indra_mqtt_codec:decode_subscribe(<<0, 7, 0, 0, 0>>)).

subscribe_bad_fixed_flags_rejected_test() ->
    %% SUBSCRIBE with flags 0000 (must be 0010).
    ?assertEqual({error, {invalid_flags, subscribe, 0}},
                 indra_mqtt_codec:decode_packet(<<16#80, 16#02, 16#00, 16#07>>)).

encode_suback_vectors_test() ->
    ?assertEqual(<<16#90, 16#03, 16#00, 16#07, 16#01>>,
                 indra_mqtt_codec:encode_suback(7, [1])),
    ?assertEqual(<<16#90, 16#04, 16#00, 16#09, 16#00, 16#02>>,
                 indra_mqtt_codec:encode_suback(9, [0, 2])),
    ?assertEqual(<<16#90, 16#03, 16#00, 16#09, 16#80>>,
                 indra_mqtt_codec:encode_suback(9, [16#80])),
    ?assertError(badarg, indra_mqtt_codec:encode_suback(9, [5])).

%%====================================================================
%% PUBLISH / PUBACK
%%====================================================================

decode_publish_qos0_test() ->
    %% Topic "t", payload "hi".
    Body = <<0, 1, "t", "hi">>,
    Bin = <<16#30, (byte_size(Body)), Body/binary>>,
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                maps:get(flags, Pkt)),
    ?assertEqual(<<"t">>, maps:get(topic, Pub)),
    ?assertEqual(0, maps:get(packet_id, Pub)),
    ?assertEqual(0, maps:get(qos, Pub)),
    ?assertEqual(false, maps:get(retain, Pub)),
    ?assertEqual(false, maps:get(dup, Pub)),
    ?assertEqual(<<"hi">>, maps:get(payload, Pub)).

decode_publish_qos1_flags_test() ->
    %% Flags 1011: DUP=1, QoS=1, RETAIN=1; topic "ab", id 16, payload "Z".
    Body = <<0, 2, "ab", 0, 16, "Z">>,
    Bin = <<16#3B, (byte_size(Body)), Body/binary>>,
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                maps:get(flags, Pkt)),
    ?assertEqual(<<"ab">>, maps:get(topic, Pub)),
    ?assertEqual(16, maps:get(packet_id, Pub)),
    ?assertEqual(1, maps:get(qos, Pub)),
    ?assertEqual(true, maps:get(retain, Pub)),
    ?assertEqual(true, maps:get(dup, Pub)),
    ?assertEqual(<<"Z">>, maps:get(payload, Pub)).

decode_publish_rejects_test() ->
    %% Empty topic.
    ?assertEqual({error, malformed_publish_topic},
                 indra_mqtt_codec:decode_publish(<<0, 0, "hi">>, 0)),
    %% Wildcard topic.
    ?assertEqual({error, invalid_publish_topic},
                 indra_mqtt_codec:decode_publish(<<0, 3, "a/#", "x">>, 0)),
    %% Truncated topic bytes.
    ?assertEqual({error, truncated_publish},
                 indra_mqtt_codec:decode_publish(<<0, 9, "short">>, 0)),
    %% QoS 1 without packet id bytes.
    ?assertEqual({error, malformed_publish_packet_id},
                 indra_mqtt_codec:decode_publish(<<0, 1, "t">>, 2)),
    %% Zero packet id on QoS 1.
    ?assertEqual({error, malformed_publish_packet_id},
                 indra_mqtt_codec:decode_publish(<<0, 1, "t", 0, 0>>, 2)).

encode_publish_roundtrip_test() ->
    lists:foreach(
      fun({Topic, Pid, QoS, Retain, Dup, Payload}) ->
          Bin = indra_mqtt_codec:encode_publish(Topic, Pid, QoS, Retain, Dup, Payload),
          {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
          ?assertEqual(publish, maps:get(type_atom, Pkt)),
          {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                      maps:get(flags, Pkt)),
          ?assertEqual(Topic, maps:get(topic, Pub)),
          ?assertEqual(QoS, maps:get(qos, Pub)),
          ?assertEqual(Retain, maps:get(retain, Pub)),
          ?assertEqual(Dup, maps:get(dup, Pub)),
          ?assertEqual(Payload, maps:get(payload, Pub)),
          ExpectedPid = case QoS of 0 -> 0; _ -> Pid end,
          ?assertEqual(ExpectedPid, maps:get(packet_id, Pub))
      end, [{<<"t">>, 0, 0, false, false, <<"hi">>},
            {<<"a/b">>, 42, 1, false, false, <<"data">>},
            {<<"a/b">>, 43, 1, true, true, <<>>},
            {<<"sport/tennis">>, 60000, 2, false, false, <<"x">>}]).

encode_publish_qos0_drops_packet_id_test() ->
    %% /4 defaults DUP/RETAIN to 0 and omits any packet id for QoS 0.
    ?assertEqual(<<16#30, 5, 0, 1, "t", "hi">>,
                 indra_mqtt_codec:encode_publish(<<"t">>, 0, 0, <<"hi">>)).

encode_publish_flag_bits_test() ->
    %% QoS 0 + RETAIN: fixed header 0011_0001.
    <<16#31, _/binary>> =
        indra_mqtt_codec:encode_publish(<<"t">>, 0, 0, true, false, <<"hi">>),
    %% QoS 1 + DUP, no RETAIN: fixed header 0011_1010.
    <<16#3A, _/binary>> =
        indra_mqtt_codec:encode_publish(<<"t">>, 7, 1, false, true, <<"hi">>),
    %% QoS 1 + RETAIN + DUP: fixed header 0011_1011, and the flags
    %% round-trip back through the decoder.
    Bin = indra_mqtt_codec:encode_publish(<<"t">>, 7, 1, true, true, <<"hi">>),
    <<16#3B, _/binary>> = Bin,
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                maps:get(flags, Pkt)),
    ?assertEqual(true, maps:get(retain, Pub)),
    ?assertEqual(true, maps:get(dup, Pub)).

encode_publish_bad_args_raise_test() ->
    ?assertError(badarg, indra_mqtt_codec:encode_publish(<<"t">>, 0, 1, <<"x">>)),
    ?assertError(function_clause,
                 indra_mqtt_codec:encode_publish(<<>>, 1, 0, <<"x">>)).

encode_puback_vector_test() ->
    ?assertEqual(<<16#40, 16#02, 16#00, 16#2A>>,
                 indra_mqtt_codec:encode_puback(42)),
    ?assertEqual(<<16#40, 16#02, 16#FF, 16#FF>>,
                 indra_mqtt_codec:encode_puback(65535)).
