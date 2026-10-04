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
    ?assertEqual(false, maps:get(will_retain, Conn)),
    %% F1-01: the will topic and message are captured for the bind.
    ?assertEqual(<<"wt">>, maps:get(will_topic, Conn)),
    ?assertEqual(<<"wm">>, maps:get(will_payload, Conn)).

decode_connect_no_will_has_no_will_strings_test() ->
    {ok, Pkt, _} = indra_mqtt_codec:decode_packet(connect_bytes(<<"s-1">>, 16#02, 60)),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(false, maps:get(will_flag, Conn)),
    ?assertEqual(undefined, maps:get(will_topic, Conn)),
    ?assertEqual(undefined, maps:get(will_payload, Conn)).

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

decode_connect_captures_will_topic_and_payload_test() ->
    %% Flags 04 (will) | 02 (clean): 0x06, QoS 0, no retain.
    Var = <<0, 4, "MQTT", 4, 16#06, 0, 60>>,
    Body = <<Var/binary, 0, 3, "cid", 0, 5, "w/bye", 0, 7, "goodbye">>,
    Bin = <<16#10, (byte_size(Body)), Body/binary>>,
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(true, maps:get(will_flag, Conn)),
    ?assertEqual(0, maps:get(will_qos, Conn)),
    ?assertEqual(false, maps:get(will_retain, Conn)),
    ?assertEqual(<<"w/bye">>, maps:get(will_topic, Conn)),
    ?assertEqual(<<"goodbye">>, maps:get(will_payload, Conn)).

decode_connect_without_will_has_no_will_fields_test() ->
    {ok, Pkt, _} = indra_mqtt_codec:decode_packet(connect_bytes(<<"s-1">>, 16#02, 60)),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(false, maps:get(will_flag, Conn)),
    ?assertEqual(undefined, maps:get(will_topic, Conn)),
    ?assertEqual(undefined, maps:get(will_payload, Conn)).

decode_connect_anonymous_has_no_credentials_test() ->
    {ok, Pkt, _} = indra_mqtt_codec:decode_packet(connect_bytes(<<"s-1">>, 16#02, 60)),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(undefined, maps:get(username, Conn)),
    ?assertEqual(undefined, maps:get(password, Conn)).

decode_connect_unsupported_protocol_test() ->
    %% Legacy MQIsdp name rejected, as is an unknown level.
    Var3 = <<0, 6, "MQIsdp", 3, 16#02, 0, 60>>,
    Body3 = <<Var3/binary, 0, 1, "a">>,
    ?assertEqual({error, {unsupported_protocol, <<"MQIsdp">>, 3}},
                 indra_mqtt_codec:decode_connect(Body3)),
    Var6 = <<0, 4, "MQTT", 6, 16#02, 0, 60>>,
    Body6 = <<Var6/binary, 0, 1, "a">>,
    ?assertEqual({error, {unsupported_protocol, <<"MQTT">>, 6}},
                 indra_mqtt_codec:decode_connect(Body6)).

decode_connect_v5_minimal_test() ->
    %% Level 5 with empty properties decodes like 3.1.1 plus the
    %% level and a zero alias maximum (B4-05).
    Var = <<0, 4, "MQTT", 5, 16#02, 0, 60>>,
    Body = <<Var/binary, 0, 0, 1, "a">>,
    {ok, Conn} = indra_mqtt_codec:decode_connect(Body),
    ?assertEqual(5, maps:get(protocol_level, Conn)),
    ?assertEqual(<<"a">>, maps:get(client_id, Conn)),
    ?assertEqual(0, maps:get(alias_max, Conn)).

decode_connect_v5_alias_maximum_test() ->
    %% Level 5 carrying Topic Alias Maximum (property 34 = 10).
    Var = <<0, 4, "MQTT", 5, 16#02, 0, 60>>,
    Body = <<Var/binary, 3, 34, 0, 10, 0, 1, "a">>,
    {ok, Conn} = indra_mqtt_codec:decode_connect(Body),
    ?assertEqual(5, maps:get(protocol_level, Conn)),
    ?assertEqual(10, maps:get(alias_max, Conn)).

decode_connect_v4_reports_zero_alias_max_test() ->
    {ok, Pkt, _} = indra_mqtt_codec:decode_packet(connect_bytes(<<"s-1">>, 16#02, 60)),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(4, maps:get(protocol_level, Conn)),
    ?assertEqual(0, maps:get(alias_max, Conn)).

%%====================================================================
%% CONNECT v5 properties (X1-01: framing + transport fields)
%%====================================================================

%% @private Build a level-5 CONNECT body with the given properties
%% block and a one-byte client id "a".
v5_connect_body(Props) ->
    Var = <<0, 4, "MQTT", 5, 16#02, 0, 60>>,
    <<Var/binary, (byte_size(Props)):8, Props/binary, 0, 1, "a">>.

decode_connect_v5_each_property_in_isolation_test() ->
    %% Session Expiry Interval (17, u32 3600).
    {ok,Expiry} =
        indra_mqtt_codec:decode_connect(v5_connect_body(<<17, 0, 0, 14, 16>>)),
    ?assertEqual(3600, maps:get(session_expiry, Expiry)),
    ?assertEqual(65535, maps:get(receive_max, Expiry)),
    %% Receive Maximum (33, u16 100).
    {ok, Recv} = indra_mqtt_codec:decode_connect(v5_connect_body(<<33, 0, 100>>)),
    ?assertEqual(100, maps:get(receive_max, Recv)),
    ?assertEqual(0, maps:get(session_expiry, Recv)),
    %% Maximum Packet Size (39, u32 65536).
    {ok, MaxPkt} =
        indra_mqtt_codec:decode_connect(v5_connect_body(<<39, 0, 1, 0, 0>>)),
    ?assertEqual(65536, maps:get(max_packet_size, MaxPkt)),
    %% Topic Alias Maximum (34, u16 10).
    {ok, Alias} = indra_mqtt_codec:decode_connect(v5_connect_body(<<34, 0, 10>>)),
    ?assertEqual(10, maps:get(alias_max, Alias)),
    %% Request Response Information (25, u8 1).
    {ok, Resp} = indra_mqtt_codec:decode_connect(v5_connect_body(<<25, 1>>)),
    ?assertEqual(true, maps:get(req_resp_info, Resp)),
    %% Request Problem Information (23, u8 0).
    {ok, Prob} = indra_mqtt_codec:decode_connect(v5_connect_body(<<23, 0>>)),
    ?assertEqual(false, maps:get(req_problem_info, Prob)),
    %% Authentication Method (21, UTF-8 "SCRAM").
    {ok, AuthM} =
        indra_mqtt_codec:decode_connect(v5_connect_body(<<21, 0, 5, "SCRAM">>)),
    ?assertEqual(<<"SCRAM">>, maps:get(auth_method, AuthM)),
    %% Authentication Data (22, binary <<1,2,3>>).
    {ok, AuthD} =
        indra_mqtt_codec:decode_connect(v5_connect_body(<<22, 0, 3, 1, 2, 3>>)),
    ?assertEqual(<<1, 2, 3>>, maps:get(auth_data, AuthD)),
    %% User Property (38, "k" -> "v").
    {ok, Users} =
        indra_mqtt_codec:decode_connect(v5_connect_body(<<38, 0, 1, "k", 0, 1, "v">>)),
    ?assertEqual([{<<"k">>, <<"v">>}], maps:get(user_properties, Users)).

decode_connect_v5_defaults_when_absent_test() ->
    %% Empty properties: every field reports its default.
    {ok, Conn} = indra_mqtt_codec:decode_connect(v5_connect_body(<<>>)),
    ?assertEqual(0, maps:get(session_expiry, Conn)),
    ?assertEqual(65535, maps:get(receive_max, Conn)),
    ?assertEqual(0, maps:get(max_packet_size, Conn)),
    ?assertEqual(false, maps:get(req_resp_info, Conn)),
    ?assertEqual(true, maps:get(req_problem_info, Conn)),
    ?assertEqual(undefined, maps:get(auth_method, Conn)),
    ?assertEqual(undefined, maps:get(auth_data, Conn)),
    ?assertEqual([], maps:get(user_properties, Conn)),
    ?assertEqual(0, maps:get(alias_max, Conn)).

decode_connect_v4_reports_v5_defaults_test() ->
    %% Level 4 has no properties section: same defaults as an empty v5
    %% block, so the bind fields below never see a version skew.
    {ok, Pkt, _} = indra_mqtt_codec:decode_packet(connect_bytes(<<"s-1">>, 16#02, 60)),
    {ok, Conn} = indra_mqtt_codec:decode_connect(maps:get(payload, Pkt)),
    ?assertEqual(0, maps:get(session_expiry, Conn)),
    ?assertEqual(65535, maps:get(receive_max, Conn)),
    ?assertEqual(0, maps:get(max_packet_size, Conn)),
    ?assertEqual([], maps:get(user_properties, Conn)).

decode_connect_v5_truncated_property_length_test() ->
    %% Property length 5 but only 2 property bytes present.
    Var = <<0, 4, "MQTT", 5, 16#02, 0, 60>>,
    ?assertEqual({error, truncated_connect},
                 indra_mqtt_codec:decode_connect(<<Var/binary, 5, 34, 0, 0, 1, "a">>)).

decode_connect_v5_overlong_properties_test() ->
    %% Duplicate single-occurrence property (two session-expiry values).
    ?assertEqual({error, malformed_connect_properties},
                 indra_mqtt_codec:decode_connect(
                   v5_connect_body(<<17, 0, 0, 0, 1, 17, 0, 0, 0, 2>>))),
    %% Request Response Information with a value outside 0 | 1.
    ?assertEqual({error, malformed_connect_properties},
                 indra_mqtt_codec:decode_connect(v5_connect_body(<<25, 2>>))).

decode_connect_v5_trailing_garbage_test() ->
    Var = <<0, 4, "MQTT", 5, 16#02, 0, 60>>,
    ?assertEqual({error, trailing_connect_bytes},
                 indra_mqtt_codec:decode_connect(
                   <<Var/binary, 0, 0, 1, "a", 16#FF>>)).

%%====================================================================
%% CONNACK v5 encoding (X1-01)
%%====================================================================

encode_connack_v5_success_vector_test() ->
    %% No session present, success, alias maximum 10 only:
    %% Body = SP(0) RC(0) PropLen(3) Props(34 0 10).
    Bin = indra_mqtt_codec:encode_connack_v5(false, 0, #{alias_max => 10}),
    ?assertEqual(<<16#20, 6, 0, 0, 3, 34, 0, 10>>, Bin),
    {ok, Dec} = indra_mqtt_codec:decode_connack_v5(binary:part(Bin, 2, 6)),
    ?assertEqual(false, maps:get(session_present, Dec)),
    ?assertEqual(0, maps:get(reason_code, Dec)),
    ?assertEqual(10, maps:get(alias_max, Dec)).

encode_connack_v5_bad_credentials_with_reason_string_test() ->
    %% Session absent, RC 16#86, reason string "bad password":
    %% Props = 28 Len(12) Str + no alias.
    Bin = indra_mqtt_codec:encode_connack_v5(
            false, 16#86, #{reason_string => <<"bad password">>}),
    {ok, Dec} = indra_mqtt_codec:decode_connack_v5(binary:part(Bin, 2, byte_size(Bin) - 2)),
    ?assertEqual(16#86, maps:get(reason_code, Dec)),
    ?assertEqual(<<"bad password">>, maps:get(reason_string, Dec)),
    ?assertEqual(undefined, maps:get(assigned_client_id, Dec)).

encode_connack_v5_user_properties_roundtrip_test() ->
    Opts = #{assigned_client_id => <<"auto-1">>,
             session_expiry => 3600,
             receive_max => 100,
             max_packet_size => 65536,
             reason_string => <<"ok">>,
             user_properties => [{<<"k">>, <<"v">>}, {<<"a">>, <<"b">>}]},
    Bin = indra_mqtt_codec:encode_connack_v5(true, 0, Opts),
    {ok, Dec} = indra_mqtt_codec:decode_connack_v5(binary:part(Bin, 2, byte_size(Bin) - 2)),
    ?assertEqual(true, maps:get(session_present, Dec)),
    ?assertEqual(<<"auto-1">>, maps:get(assigned_client_id, Dec)),
    ?assertEqual(3600, maps:get(session_expiry, Dec)),
    ?assertEqual(100, maps:get(receive_max, Dec)),
    ?assertEqual(65536, maps:get(max_packet_size, Dec)),
    ?assertEqual([{<<"k">>, <<"v">>}, {<<"a">>, <<"b">>}],
                 maps:get(user_properties, Dec)).

encode_connack_v5_empty_props_vector_test() ->
    %% No properties at all: PropLen 0, body is 3 bytes.
    Bin = indra_mqtt_codec:encode_connack_v5(false, 0, #{}),
    ?assertEqual(<<16#20, 3, 0, 0, 0>>, Bin).

encode_connack_v4_shape_unchanged_test() ->
    %% The 3.1.1 encoder is untouched by the v5 work: fixed 4-byte
    %% shape whatever the session flags are.
    ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>,
                 indra_mqtt_codec:encode_connack(false, 0)),
    ?assertEqual(<<16#20, 16#02, 16#01, 16#00>>,
                 indra_mqtt_codec:encode_connack(true, 0)).

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

encode_suback_multibyte_remaining_length_test() ->
    %% 126 granted codes: the body is 128 bytes, so the Remaining
    %% Length must use the two-byte form <<16#80, 16#01>>. The old
    %% single-byte form emitted 16#80 here, whose continuation bit
    %% makes every spec-compliant reader swallow the packet id as a
    %% length byte and desynchronise the whole stream (short PUBLISH
    %% bodies and shifted payloads downstream).
    Codes126 = lists:duplicate(126, 0),
    Bin126 = indra_mqtt_codec:encode_suback(7, Codes126),
    <<16#90, 16#80, 16#01, Body126/binary>> = Bin126,
    ?assertEqual(128, byte_size(Body126)),
    {ok, Pkt126, <<>>} = indra_mqtt_codec:decode_packet(Bin126),
    ?assertEqual(128, maps:get(remaining_length, Pkt126)),
    %% 200 codes round-trip through the generic framing path with the
    %% granted codes intact.
    Codes200 = lists:duplicate(200, 1),
    Bin200 = indra_mqtt_codec:encode_suback(9, Codes200),
    {ok, Pkt200, <<>>} = indra_mqtt_codec:decode_packet(Bin200),
    ?assertEqual(202, maps:get(remaining_length, Pkt200)),
    ?assertEqual(<<0, 9, (binary:copy(<<1>>, 200))/binary>>,
                 maps:get(payload, Pkt200)).

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

connack_return_code_maps_kernel_reason_codes_test() ->
    %% MQTT 3.1.1 return codes pass through unchanged.
    lists:foreach(fun(RC) ->
                          ?assertEqual(RC, indra_mqtt_codec:connack_return_code(RC))
                  end, lists:seq(0, 5)),
    %% MQTT 5 reason codes from the kernel fold into 3.1.1 codes.
    ?assertEqual(2, indra_mqtt_codec:connack_return_code(16#85)),
    ?assertEqual(4, indra_mqtt_codec:connack_return_code(16#86)),
    ?assertEqual(5, indra_mqtt_codec:connack_return_code(16#87)),
    ?assertEqual(3, indra_mqtt_codec:connack_return_code(16#8B)).

alias_property_helpers_roundtrip_test() ->
    %% Topic Alias Maximum property values round-trip (B4-05).
    lists:foreach(fun(Max) ->
                          ?assertEqual({ok, Max},
                                       indra_mqtt_codec:decode_alias_maximum(
                                         indra_mqtt_codec:encode_alias_maximum(Max)))
                  end, [0, 1, 10, 65535]),
    ?assertEqual({error, malformed_alias_maximum},
                 indra_mqtt_codec:decode_alias_maximum(<<0>>)),
    %% Topic Alias property values round-trip.
    lists:foreach(fun(Alias) ->
                          ?assertEqual({ok, Alias},
                                       indra_mqtt_codec:decode_topic_alias(
                                         indra_mqtt_codec:encode_topic_alias(Alias)))
                  end, [0, 1, 7, 65535]),
    ?assertEqual({error, malformed_topic_alias},
                 indra_mqtt_codec:decode_topic_alias(<<>>)).

alias_in_range_rejects_zero_and_over_max_test() ->
    ?assertEqual(false, indra_mqtt_codec:alias_in_range(0, 10)),
    ?assertEqual(false, indra_mqtt_codec:alias_in_range(1, 0)),
    ?assertEqual(false, indra_mqtt_codec:alias_in_range(11, 10)),
    ?assertEqual(true, indra_mqtt_codec:alias_in_range(1, 10)),
    ?assertEqual(true, indra_mqtt_codec:alias_in_range(10, 10)).

decode_publish_reports_zero_alias_test() ->
    %% The 3.1.1 wire carries no alias property, so the edge always
    %% reports the alias absent (B4-05).
    Body = <<0, 1, "t", "hi">>,
    Bin = <<16#30, (byte_size(Body)), Body/binary>>,
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                maps:get(flags, Pkt)),
    ?assertEqual(0, maps:get(alias, Pub)),
    ?assertEqual(false, maps:get(alias_present, Pub)).

decode_publish_v5_alias_property_test() ->
    %% Level 5 QoS 0: topic "t" plus Topic Alias 7 (property 35).
    %% Properties block is <<3, 35, 0, 7>> (length 3, id 35, value 7).
    Body = <<0, 1, "t", 3, 35, 0, 7, "hi">>,
    {ok, Pub} = indra_mqtt_codec:decode_publish(Body, 0, 5),
    ?assertEqual(<<"t">>, maps:get(topic, Pub)),
    ?assertEqual(7, maps:get(alias, Pub)),
    ?assertEqual(true, maps:get(alias_present, Pub)),
    ?assertEqual(<<"hi">>, maps:get(payload, Pub)).

decode_publish_v5_empty_topic_alias_reference_test() ->
    %% Level 5 alias-by-reference: empty topic with alias 7 resolves
    %% downstream; the payload still arrives intact.
    Body = <<0, 0, 3, 35, 0, 7, "hi">>,
    {ok, Pub} = indra_mqtt_codec:decode_publish(Body, 0, 5),
    ?assertEqual(<<>>, maps:get(topic, Pub)),
    ?assertEqual(7, maps:get(alias, Pub)),
    ?assertEqual(true, maps:get(alias_present, Pub)),
    ?assertEqual(<<"hi">>, maps:get(payload, Pub)).

decode_publish_v5_no_alias_reports_absent_test() ->
    %% Level 5 without properties (length 0) reports the alias absent,
    %% never an explicit 0.
    Body = <<0, 1, "t", 0, "hi">>,
    {ok, Pub} = indra_mqtt_codec:decode_publish(Body, 0, 5),
    ?assertEqual(0, maps:get(alias, Pub)),
    ?assertEqual(false, maps:get(alias_present, Pub)).

decode_publish_v5_empty_topic_without_alias_rejected_test() ->
    %% Empty topic with no alias property is malformed on either level.
    ?assertEqual({error, malformed_publish_topic},
                 indra_mqtt_codec:decode_publish(<<0, 0, 0, "hi">>, 0, 5)).

decode_publish_level4_still_rejects_empty_topic_test() ->
    ?assertEqual({error, malformed_publish_topic},
                 indra_mqtt_codec:decode_publish(<<0, 0, "hi">>, 0, 4)).

%%====================================================================
%% SUBSCRIBE v5 options (X1-03)
%%====================================================================

decode_subscribe_v5_opts_roundtrip_test() ->
    %% Packet id 7, no properties, one filter "a/b" with Opts QoS1|NL|RH1:
    %% Opts = 1 | 16#04 | 16#10 = 16#15.
    Opts = indra_mqtt_codec:encode_subscribe_opts(1, true, false, 1),
    ?assertEqual(16#15, Opts),
    Body = <<0, 7, 0, 0, 3, "a/b", Opts>>,
    {ok, Sub} = indra_mqtt_codec:decode_subscribe(Body, 5),
    ?assertEqual(7, maps:get(packet_id, Sub)),
    ?assertEqual([{<<"a/b">>, Opts}], maps:get(subscriptions, Sub)),
    ?assertEqual(0, maps:get(sub_id, Sub)),
    {ok, {1, true, false, 1}} = indra_mqtt_codec:decode_subscribe_opts(Opts).

decode_subscribe_v5_sub_id_applies_packet_wide_test() ->
    %% Subscription Identifier 42 (property 11) applies to every filter.
    Props = <<11, 42>>,
    Body = <<0, 9, (byte_size(Props)):8, Props/binary,
             0, 1, "a", 0, 0, 1, "b", 2>>,
    {ok, Sub} = indra_mqtt_codec:decode_subscribe(Body, 5),
    ?assertEqual(42, maps:get(sub_id, Sub)),
    ?assertEqual([{<<"a">>, 0}, {<<"b">>, 2}], maps:get(subscriptions, Sub)).

decode_subscribe_v5_reserved_bits_ride_through_test() ->
    %% Reserved bits set: the edge passes the byte through (the kernel
    %% fails only that filter with 16#8F); the packet itself decodes.
    Body = <<0, 7, 0, 0, 1, "a", 16#C1>>,
    {ok, Sub} = indra_mqtt_codec:decode_subscribe(Body, 5),
    ?assertEqual([{<<"a">>, 16#C1}], maps:get(subscriptions, Sub)),
    ?assertEqual({error, {invalid_subscribe_opts, 16#C1}},
                 indra_mqtt_codec:decode_subscribe_opts(16#C1)).

decode_subscribe_v4_bytes_unchanged_test() ->
    %% Level 4 decodes exactly as before (strict QoS, no properties).
    Body = <<0, 7, 0, 1, "a", 1>>,
    {ok, Sub} = indra_mqtt_codec:decode_subscribe(Body, 4),
    ?assertEqual([{<<"a">>, 1}], maps:get(subscriptions, Sub)).

encode_suback_v5_vectors_test() ->
    %% Packet id 7, codes [1, 16#87] with empty properties.
    Bin = indra_mqtt_codec:encode_suback_v5(7, [1, 16#87], #{}),
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(suback, maps:get(type_atom, Pkt)),
    {ok, Dec} = indra_mqtt_codec:decode_suback_v5(maps:get(payload, Pkt)),
    ?assertEqual(7, maps:get(packet_id, Dec)),
    ?assertEqual([1, 16#87], maps:get(codes, Dec)).

encode_suback_v4_shape_unchanged_test() ->
    %% The 3.1.1 SUBACK encoder is untouched by the v5 work.
    ?assertEqual(<<16#90, 16#03, 16#00, 16#07, 16#01>>,
                 indra_mqtt_codec:encode_suback(7, [1])).

decode_publish_v5_user_props_roundtrip_test() ->
    %% Level 5 QoS 0: topic "t", user property "k"->"v", payload "hi".
    %% Props = 38 Len("k") "k" Len("v") "v" (9 bytes).
    Props = <<38, 0, 1, "k", 0, 1, "v">>,
    Body = <<0, 1, "t", (byte_size(Props)), Props/binary, "hi">>,
    {ok, Pub} = indra_mqtt_codec:decode_publish(Body, 0, 5),
    ?assertEqual([{<<"k">>, <<"v">>}], maps:get(user_properties, Pub)),
    ?assertEqual(0, maps:get(payload_format, Pub)),
    ?assertEqual(<<"hi">>, maps:get(payload, Pub)).

decode_publish_v5_inbound_sub_id_rejected_test() ->
    %% A client sending a subscription identifier fails closed.
    Props = <<11, 42>>,
    Body = <<0, 1, "t", (byte_size(Props)), Props/binary, "hi">>,
    ?assertMatch({error, _},
                 indra_mqtt_codec:decode_publish(Body, 0, 5)).

encode_publish_v5_sub_id_vector_test() ->
    %% Delivery with subscription identifier 7 carries property 11 on
    %% the wire (server-to-client; inbound client publishes with 11
    %% are rejected above, so this asserts framing only).
    Bin = indra_mqtt_codec:encode_publish_v5(<<"t">>, 0, 0, false, false,
                                             <<"hi">>, 0, 7),
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(publish, maps:get(type_atom, Pkt)),
    Payload = maps:get(payload, Pkt),
    %% Topic "t" (3 bytes) then property length + <<11, 7>> then "hi".
    ?assert(binary:match(Payload, <<11, 7>>) =/= nomatch),
    %% SubId 0 encodes exactly like the alias-only shape (no property).
    Bin0 = indra_mqtt_codec:encode_publish_v5(<<"t">>, 0, 0, false, false,
                                              <<"hi">>, 0, 0),
    ?assertEqual(nomatch, binary:match(Bin0, <<11, 7>>)).

encode_publish_v5_full_forwards_props_test() ->
    %% Delivery with identifier plus format and user properties carries
    %% all three on the wire; the empty form stays property-less.
    Bin = indra_mqtt_codec:encode_publish_v5_full(
            <<"t">>, 0, 0, false, false, <<"hi">>, 0, 7, 1, 0,
            [{<<"k">>, <<"v">>}]),
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(publish, maps:get(type_atom, Pkt)),
    Payload = maps:get(payload, Pkt),
    ?assert(binary:match(Payload, <<11, 7>>) =/= nomatch),
    ?assert(binary:match(Payload, <<1, 1>>) =/= nomatch),
    ?assert(binary:match(Payload, <<"k">>) =/= nomatch),
    Empty = indra_mqtt_codec:encode_publish_v5_full(
              <<"t">>, 0, 0, false, false, <<"hi">>, 0, 0, 0, 0, []),
    ?assertEqual(nomatch, binary:match(Empty, <<11, 7>>)).

decode_disconnect_v5_vectors_test() ->
    %% Empty body means normal disconnection.
    {ok, D0} = indra_mqtt_codec:decode_disconnect_v5(<<>>),
    ?assertEqual(0, maps:get(reason_code, D0)),
    %% Code 4 with empty properties decodes with no reason string.
    {ok, D4} = indra_mqtt_codec:decode_disconnect_v5(<<4, 0>>),
    ?assertEqual(4, maps:get(reason_code, D4)),
    ?assertEqual(<<>>, maps:get(reason_string, D4)),
    %% Encode/decode round-trip with a reason string.
    Bin = indra_mqtt_codec:encode_disconnect_v5(16#94, <<"bad alias">>),
    {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(Bin),
    ?assertEqual(disconnect, maps:get(type_atom, Pkt)),
    {ok, Dec} = indra_mqtt_codec:decode_disconnect_v5(maps:get(payload, Pkt)),
    ?assertEqual(16#94, maps:get(reason_code, Dec)),
    ?assertEqual(<<"bad alias">>, maps:get(reason_string, Dec)),
    %% Code 0 with no properties keeps the 2-byte 3.1.1 shape.
    ?assertEqual(<<16#E0, 16#00>>,
                 indra_mqtt_codec:encode_disconnect_v5(0, <<>>)).
