%% @doc Zero-copy MQTT 3.1.1 fixed-header codec (BEAM edge side).
%%
%% The BEAM appliance owns sockets and framing only; it parses just enough
%% of each MQTT packet to route bytes (packet type, flags, remaining
%% length) while leaving session semantics to the Rust core.
%%
%% All decoders use binary pattern matching over the input binary and
%% return sub-binaries that reference the original input (no copying).
-module(indra_mqtt_codec).

-export([decode_packet/1,
         decode_remaining_length/1,
         encode_remaining_length/1,
         decode_connect/1,
         encode_connack/2,
         encode_connack/3,
         encode_connack_v5/3,
         decode_connack_v5/1,
         connack_return_code/1,
          decode_subscribe/1,
          decode_subscribe/2,
          encode_suback/2,
          encode_suback_v5/3,
          decode_suback_v5/1,
          decode_publish/2,
          decode_publish/3,
          encode_publish/4,
          encode_publish/6,
          encode_publish/7,
          encode_puback/1,
          encode_pubrec/1,
          encode_pubrec/2,
          encode_pubrel/1,
          encode_pubcomp/1,
          encode_publish_v5/8,
          encode_publish_v5_full/11,
          decode_disconnect_v5/1,
          encode_disconnect_v5/2,
          encode_disconnect_v5/3,
          decode_subscribe_opts/1,
          encode_subscribe_opts/4,
          packet_type_atom/1,
          packet_type_code/1]).

%% Topic-alias property helpers (B4-05, CONNECT/CONNACK/PUBLISH only).
%% The edge decodes 3.1.1 plus the MQTT 5 alias properties (34/35) so a
%% v5 client can negotiate and use aliases on the socket; 3.1.1 clients
%% keep the previous framing exactly. Table ownership: the kernel session
%% holds both tables; CONNECT writes the two maxima, PUBLISH writes
%% inbound entries, delivery writes outbound entries. The helpers below
%% frame the on-wire property values and are called by the CONNACK and
%% PUBLISH paths (never test-only).
-export([encode_alias_maximum/1,
         decode_alias_maximum/1,
         encode_topic_alias/1,
         decode_topic_alias/1,
         alias_in_range/2]).

-define(MAX_REMAINING, 268435455).
-define(MAX_TOPIC_LEN, 65535).
%% Property identifiers (CONNECT/CONNACK/PUBLISH properties).
-define(ALIAS_MAXIMUM_PROPERTY_ID, 34).
%% Property identifier for the PUBLISH alias property.
-define(TOPIC_ALIAS_PROPERTY_ID, 35).
%% Reason code rejecting an unusable alias.
-define(REASON_TOPIC_ALIAS_INVALID, 16#94).
%% Largest alias value the wire format carries (u16, minus 0).
-define(MAX_TOPIC_ALIAS, 65535).
%% MQTT 5 CONNECT/CONNACK property identifiers carried on this path.
-define(PROP_SESSION_EXPIRY, 17).
-define(PROP_AUTH_METHOD, 21).
-define(PROP_AUTH_DATA, 22).
-define(PROP_REQ_PROBLEM_INFO, 23).
-define(PROP_REQ_RESP_INFO, 25).
-define(PROP_REASON_STRING, 28).
-define(PROP_RECV_MAXIMUM, 33).
-define(PROP_USER_PROPERTY, 38).
-define(PROP_MAX_PACKET_SIZE, 39).
-define(PROP_ASSIGNED_CLIENT_ID, 18).
%% X1-03 v5 SUBSCRIBE/PUBLISH/DISCONNECT property identifiers.
-define(PROP_PAYLOAD_FORMAT, 1).
-define(PROP_MSG_EXPIRY, 2).
-define(PROP_SUB_ID, 11).
%% Largest subscription identifier on the wire (varint maximum). Reason:
%% the identifier rides a variable-byte integer, so a larger value can
%% never arrive as a single property; 0 means absent and is never valid
%% on the wire. One u32 per subscription, no new unbounded state.
-define(MAX_SUB_ID, 268435455).
%% Largest v5 SUBSCRIBE/SUBACK/DISCONNECT properties block the edge
%% accepts (bytes). Reason: one properties block must fit the 65535-byte
%% BrokerLink meta cap downstream once framed; a larger block fails the
%% packet closed instead of registering half a subscription.
-define(MAX_V5_SUB_PROPS_LEN, 65535).
%% Most subscription identifiers carried per PUBLISH delivery (count).
%% Reason: one delivery fans out as one frame per match, each carrying
%% its own single identifier, so the wire property count stays 0 or 1;
%% the bound covers the single-id fast path with no new unbounded state.
-define(MAX_V5_SUB_IDS, 1).
%% v5 SUBACK reason codes carried per filter (granted QoS 0-2 plus the
%% documented refusals). Version-4 peers only ever observe 0-2 and 16#80.
-define(SUBACK_RC_FILTER_INVALID, 16#8F).
-define(SUBACK_RC_NOT_AUTHORIZED, 16#87).
-define(SUBACK_RC_QUOTA_EXCEEDED, 16#97).
%% Largest CONNECT properties block the edge accepts (bytes). Reason: one
%% CONNECT properties block must fit the 65535-byte BrokerLink meta cap
%% downstream once framed into a bind; a larger block fails closed instead
%% of registering half a connection.
-define(MAX_CONNECT_PROPS_LEN, 65535).
%% Largest CONNACK properties block the edge emits (bytes). Reason: a
%% CONNACK is a single small control packet; a larger block means a caller
%% bug (runaway user properties), so encode refuses instead of shedding.
-define(MAX_CONNACK_PROPS_LEN, 65535).
%% Most user properties carried per CONNECT/CONNACK (count). Reason: bounds
%% per-connection memory on the handshake path; mirrors the 16-SAN bound on
%% the bind certificate section.
-define(MAX_V5_USER_PROPS, 16).
%% Largest single user-property key, value, authentication-method or reason
%% string (bytes). Reason: bounds per-connection memory on the handshake
%% path; mirrors the 1024-byte bound on bind certificate fields.
-define(MAX_V5_PROP_STRING_LEN, 1024).

-type packet_map() :: #{type := 1..14,
                        type_atom := atom(),
                        flags := 0..15,
                        remaining_length := non_neg_integer(),
                        payload := binary()}.
-type connect_map() :: #{protocol_name := binary(),
                         protocol_level := 4 | 5,
                         clean_start := boolean(),
                         keepalive := 0..65535,
                         client_id := binary(),
                         username_flag := boolean(),
                         password_flag := boolean(),
                         username := binary() | undefined,
                         password := binary() | undefined,
                         will_flag := boolean(),
                         will_qos := 0..2,
                         will_retain := boolean(),
                         will_topic := binary() | undefined,
                         will_payload := binary() | undefined,
                         alias_max := 0..65535,
                         session_expiry := 0..4294967295,
                         receive_max := 0..65535,
                         max_packet_size := 0..4294967295,
                         req_resp_info := boolean(),
                         req_problem_info := boolean(),
                         auth_method := binary() | undefined,
                         auth_data := binary() | undefined,
                         user_properties := [{binary(), binary()}]}.
-type connack_v5_opts() :: #{assigned_client_id => binary(),
                             session_expiry => 0..4294967295,
                             receive_max => 0..65535,
                             max_packet_size => 0..4294967295,
                             reason_string => binary(),
                             user_properties => [{binary(), binary()}],
                             alias_max => 0..65535}.
-type connack_v5_map() :: #{session_present := boolean(),
                            reason_code := 0..255,
                            assigned_client_id := binary() | undefined,
                            session_expiry := 0..4294967295 | undefined,
                            receive_max := 0..65535 | undefined,
                            max_packet_size := 0..4294967295 | undefined,
                            reason_string := binary() | undefined,
                            user_properties := [{binary(), binary()}]}.
%% Note: when the kernel inbound alias maximum (property 34) rides the
%% CONNACK, `decode_connack_v5/1' additionally returns `alias_max'.
%% X1-03 v5 subscriptions carry per-filter options: `{Filter, Opts}'
%% where `Opts' is the raw subscription-options byte (bits 0-1 QoS, bit
%% 2 no-local, bit 3 retain-as-published, bits 4-5 retain handling,
%% bits 6-7 reserved). The edge passes the byte through even when
%% reserved bits are set; the kernel fails only that filter with 16#8F.
%% `sub_id' is the packet-wide subscription identifier (0 when absent).
-type subscribe_map() :: #{packet_id := 1..65535,
                           subscriptions := [{binary(), 0..255}],
                           sub_id => 0..268435455}.
-type publish_map() :: #{topic := binary(),
                         packet_id := 0..65535,
                         qos := 0..2,
                         retain := boolean(),
                         dup := boolean(),
                         alias := 0..65535,
                         alias_present := boolean(),
                         payload_format => 0..1,
                         message_expiry => 0..4294967295,
                         sub_ids => [0..268435455],
                         user_properties => [{binary(), binary()}],
                         payload := binary()}.
-type suback_v5_map() :: #{packet_id := 1..65535,
                           codes := [0..255],
                           reason_string => binary(),
                           user_properties => [{binary(), binary()}]}.
-type disconnect_v5_map() :: #{reason_code := 0..255,
                               reason_string => binary(),
                               user_properties => [{binary(), binary()}] }.

%%=============================================================%% Public API
%%=============================================================
%% @doc Decode one MQTT packet from the front of Binary.
%%
%% Returns {@code {ok, Packet, Rest}} where Packet is a map with
%% {@code type}, {@code type_atom}, {@code flags},
%% {@code remaining_length} and a zero-copy {@code payload} slice;
%% {@code {more, Need}} when more wire bytes are needed; or
%% {@code {error, Reason}} for malformed input.
-spec decode_packet(binary()) ->
    {ok, packet_map(), binary()} | {more, pos_integer()} | {error, term()}.
decode_packet(<<>>) ->
    {more, 1};
decode_packet(<<Type:4, Flags:4, Rest/binary>>) ->
    case is_valid_type(Type) of
        false ->
            {error, {invalid_packet_type, Type}};
        true ->
            case validate_flags(Type, Flags) of
                ok ->
                    case decode_remaining_length(Rest) of
                        {ok, RemLen, HeaderSize} ->
                            Need = HeaderSize + RemLen,
                            if
                                byte_size(Rest) < Need ->
                                    {more, Need - byte_size(Rest)};
                                true ->
                                    %% Sub-binaries below reference Rest
                                    %% (hence the caller input): no copying.
                                    <<_:HeaderSize/binary,
                                      Payload:RemLen/binary,
                                      Tail/binary>> = Rest,
                                    Packet = #{type => Type,
                                               type_atom => packet_type_atom(Type),
                                               flags => Flags,
                                               remaining_length => RemLen,
                                               payload => Payload},
                                    {ok, Packet, Tail}
                            end;
                        {more, _} = More ->
                            More;
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end
    end;
decode_packet(_NotBinary) ->
    {error, badarg}.

%% @doc Decode an MQTT variable-byte Remaining Length from the front.
%%
%% Returns {@code {ok, Value, BytesConsumed}}, {@code {more, 1}} when
%% the length field is truncated, or {@code {error, malformed_remaining_length}}.
-spec decode_remaining_length(binary()) ->
    {ok, non_neg_integer(), pos_integer()} | {more, pos_integer()} | {error, term()}.
decode_remaining_length(Bin) when is_binary(Bin) ->
    decode_rl(Bin, 0, 0).

%% @doc Encode a Remaining Length value (0..268435455) to its wire form.
-spec encode_remaining_length(non_neg_integer()) -> binary().
encode_remaining_length(N) when is_integer(N), N >= 0, N =< ?MAX_REMAINING ->
    encode_rl(N, <<>>).

%% @doc Decode an MQTT CONNECT variable header + payload (B4-05: 3.1.1
%% and MQTT 5).
%%
%% Takes the zero-copy {@code payload} slice produced by
%% {@code decode_packet/1} for a CONNECT packet and extracts the
%% connection parameters the edge needs for the BrokerLink handshake.
%% All returned binaries reference the input (no copying). Level 5
%% carries a properties section after the keepalive; the Topic Alias
%% Maximum (property 34) is extracted into {@code alias_max} (the
%% client's receive limit bounding the kernel outbound table, 0 when
%% absent). Level 4 has no properties and always reports
%% {@code alias_max => 0}.
-spec decode_connect(binary()) -> {ok, connect_map()} | {error, term()}.
decode_connect(<<NameLen:16/big, Rest/binary>>) ->
    case Rest of
        <<ProtoName:NameLen/binary, Level:8, Flags:8, Keepalive:16/big, Payload/binary>> ->
            case {ProtoName, Level} of
                {<<"MQTT">>, 4} ->
                    decode_connect_flags(Flags, Keepalive, Payload, 4, 0);
                {<<"MQTT">>, 5} ->
                    decode_connect_v5(Flags, Keepalive, Payload);
                _ ->
                    {error, {unsupported_protocol, ProtoName, Level}}
            end;
        _ ->
            {error, truncated_connect}
    end;
decode_connect(_) ->
    {error, truncated_connect}.

%% @doc Encode an MQTT 3.1.1 CONNACK packet.
-spec encode_connack(boolean(), 0..255) -> binary().
encode_connack(SessionPresent, ReturnCode)
  when is_boolean(SessionPresent),
       is_integer(ReturnCode), ReturnCode >= 0, ReturnCode =< 255 ->
    SP = case SessionPresent of true -> 1; false -> 0 end,
    <<16#20, 16#02, SP:8, ReturnCode:8>>.

%% @doc Encode an MQTT 5 CONNACK carrying the Topic Alias Maximum (B4-05).
%% MQTT 5 peers only: the caller must gate on the negotiated protocol
%% level and use {@link encode_connack/2} for 3.1.1 peers (a property
%% section on a 3.1.1 CONNACK breaks their fixed 4-byte shape).
%% AliasMax 0 encodes exactly like {@link encode_connack/2} (no
%% property); a nonzero maximum appends the alias-maximum property
%% (`34:u8 | value:u16be' framed by {@link encode_alias_maximum/1}) after
%% a one-byte property length, so a socket client can negotiate aliases.
%% The kernel inbound bound rides here; the edge calls this from the
%% session-binding path for level-5 bindings that carry a maximum.
-spec encode_connack(boolean(), 0..255, 0..65535) -> binary().
encode_connack(SessionPresent, ReturnCode, 0) ->
    encode_connack(SessionPresent, ReturnCode);
encode_connack(SessionPresent, ReturnCode, AliasMax)
  when is_boolean(SessionPresent),
       is_integer(ReturnCode), ReturnCode >= 0, ReturnCode =< 255,
       is_integer(AliasMax), AliasMax >= 1, AliasMax =< ?MAX_TOPIC_ALIAS ->
    SP = case SessionPresent of true -> 1; false -> 0 end,
    MaxBin = encode_alias_maximum(AliasMax),
    Props = <<?ALIAS_MAXIMUM_PROPERTY_ID:8, MaxBin/binary>>,
    Body = <<SP:8, ReturnCode:8, (byte_size(Props)):8, Props/binary>>,
    RL = encode_remaining_length(byte_size(Body)),
    <<16#20, RL/binary, Body/binary>>.

%% @doc Encode an MQTT 5 CONNACK packet (X1-01, v5 connections only).
%%
%% Wire form: `CONNACK | Remaining | AckFlags:8 | ReasonCode:8 |
%% PropertyLength:varint | Properties'. The caller must gate on the
%% negotiated protocol level and use {@link encode_connack/2} (or /3 for
%% the alias-only shape) for 3.1.1 peers. Reason codes ride unmapped:
%% the kernel answers with v5 reason codes (0 success, 16#86 bad user
%% name or password, 16#87 not authorized, ...) and a v5 client reads
%% them directly, unlike the 3.1.1 fold in {@link connack_return_code/1}.
%% Opts carries the properties to advertise; every key is optional:
%% <ul>
%% <li>`session_expiry' (u32, property 17) — omitted when absent.</li>
%% <li>`assigned_client_id' (UTF-8, property 18) — omitted when absent.</li>
%% <li>`receive_max' (u16, property 33) — omitted when 0 or absent.</li>
%% <li>`max_packet_size' (u32, property 39) — omitted when 0 or absent.</li>
%% <li>`reason_string' (UTF-8, property 28) — omitted when absent/empty.</li>
%% <li>`user_properties' ([{Key, Value}]) — one property 38 per pair.</li>
%% <li>`alias_max' (u16, property 34, the CONNACK Topic Alias Maximum)
%% — omitted when 0 or absent.</li>
%% </ul>
%% Each string is bounded by `MAX_V5_PROP_STRING_LEN' and the list by
%% `MAX_V5_USER_PROPS'; the whole block by `MAX_CONNACK_PROPS_LEN'.
%% Violations raise `error(badarg)' (caller bug, never a half packet).
-spec encode_connack_v5(boolean(), 0..255, connack_v5_opts()) -> binary().
encode_connack_v5(SessionPresent, ReasonCode, Opts)
  when is_boolean(SessionPresent),
       is_integer(ReasonCode), ReasonCode >= 0, ReasonCode =< 255,
       is_map(Opts) ->
    SP = case SessionPresent of true -> 1; false -> 0 end,
    Props = encode_connack_v5_props(Opts),
    true = (byte_size(Props) =< ?MAX_CONNACK_PROPS_LEN) orelse erlang:error(badarg),
    PropLen = encode_varint(byte_size(Props)),
    Body = <<SP:8, ReasonCode:8, PropLen/binary, Props/binary>>,
    RL = encode_remaining_length(byte_size(Body)),
    <<16#20, RL/binary, Body/binary>>.

%% @doc Decode an MQTT 5 CONNACK body (the variable header after the
%% fixed header) back into its fields. Used by EUnit vectors and any
%% future v5 client path; the edge accept path only encodes.
-spec decode_connack_v5(binary()) -> {ok, connack_v5_map()} | {error, term()}.
decode_connack_v5(<<SP:8, RC:8, Rest/binary>>) when SP =:= 0; SP =:= 1 ->
    case decode_varint(Rest) of
        {ok, PropLen, Rest1} ->
            case byte_size(Rest1) < PropLen of
                true ->
                    {error, truncated_connack};
                false ->
                    <<Props:PropLen/binary, Tail/binary>> = Rest1,
                    case Tail of
                        <<>> ->
                            case parse_connack_props(Props) of
                                {ok, Parsed} ->
                                    {ok, Parsed#{session_present => SP =:= 1,
                                                 reason_code => RC}};
                                {error, _} = Err ->
                                    Err
                            end;
                        _ ->
                            {error, trailing_connack_bytes}
                    end
            end;
        {error, _} = Err ->
            Err
    end;
decode_connack_v5(_) ->
    {error, malformed_connack}.

%% @private Encode the CONNACK v5 property block from Opts.
encode_connack_v5_props(Opts) ->
    Parts = [encode_connack_prop_session_expiry(maps:get(session_expiry, Opts, undefined)),
             encode_connack_prop_assigned_id(maps:get(assigned_client_id, Opts, undefined)),
             encode_connack_prop_recv_max(maps:get(receive_max, Opts, undefined)),
             encode_connack_prop_max_pkt(maps:get(max_packet_size, Opts, undefined)),
             encode_connack_prop_reason(maps:get(reason_string, Opts, undefined)),
             encode_connack_prop_users(maps:get(user_properties, Opts, [])),
             encode_connack_prop_alias_max(maps:get(alias_max, Opts, undefined))],
    iolist_to_binary(Parts).

encode_connack_prop_alias_max(undefined) -> <<>>;
encode_connack_prop_alias_max(0) -> <<>>;
encode_connack_prop_alias_max(V) when is_integer(V), V >= 1, V =< ?MAX_TOPIC_ALIAS ->
    <<?ALIAS_MAXIMUM_PROPERTY_ID:8, V:16/big>>;
encode_connack_prop_alias_max(_) -> erlang:error(badarg).

encode_connack_prop_session_expiry(undefined) -> <<>>;
encode_connack_prop_session_expiry(V)
  when is_integer(V), V >= 0, V =< 16#FFFFFFFF ->
    <<?PROP_SESSION_EXPIRY:8, V:32/big>>;
encode_connack_prop_session_expiry(_) -> erlang:error(badarg).

encode_connack_prop_assigned_id(undefined) -> <<>>;
encode_connack_prop_assigned_id(Id) when is_binary(Id), byte_size(Id) > 0,
                                         byte_size(Id) =< ?MAX_V5_PROP_STRING_LEN ->
    <<?PROP_ASSIGNED_CLIENT_ID:8, (byte_size(Id)):16/big, Id/binary>>;
encode_connack_prop_assigned_id(_) -> erlang:error(badarg).

encode_connack_prop_recv_max(undefined) -> <<>>;
encode_connack_prop_recv_max(0) -> <<>>;
encode_connack_prop_recv_max(V) when is_integer(V), V >= 1, V =< 65535 ->
    <<?PROP_RECV_MAXIMUM:8, V:16/big>>;
encode_connack_prop_recv_max(_) -> erlang:error(badarg).

encode_connack_prop_max_pkt(undefined) -> <<>>;
encode_connack_prop_max_pkt(0) -> <<>>;
encode_connack_prop_max_pkt(V) when is_integer(V), V >= 1, V =< 16#FFFFFFFF ->
    <<?PROP_MAX_PACKET_SIZE:8, V:32/big>>;
encode_connack_prop_max_pkt(_) -> erlang:error(badarg).

encode_connack_prop_reason(undefined) -> <<>>;
encode_connack_prop_reason(<<>>) -> <<>>;
encode_connack_prop_reason(S) when is_binary(S), byte_size(S) >= 1,
                                   byte_size(S) =< ?MAX_V5_PROP_STRING_LEN ->
    <<?PROP_REASON_STRING:8, (byte_size(S)):16/big, S/binary>>;
encode_connack_prop_reason(_) -> erlang:error(badarg).

encode_connack_prop_users([]) -> <<>>;
encode_connack_prop_users(Pairs) when is_list(Pairs) ->
    true = (length(Pairs) =< ?MAX_V5_USER_PROPS) orelse erlang:error(badarg),
    lists:foldl(
      fun({K, V}, Acc) when is_binary(K), is_binary(V),
                             byte_size(K) >= 1, byte_size(K) =< ?MAX_V5_PROP_STRING_LEN,
                             byte_size(V) =< ?MAX_V5_PROP_STRING_LEN ->
              <<Acc/binary, ?PROP_USER_PROPERTY:8,
                (byte_size(K)):16/big, K/binary,
                (byte_size(V)):16/big, V/binary>>;
         (_, _) ->
              erlang:error(badarg)
      end, <<>>, Pairs);
encode_connack_prop_users(_) -> erlang:error(badarg).

%% @private Parse a CONNACK v5 property block. Duplicates of
%% single-occurrence properties fail closed; user properties accumulate.
parse_connack_props(Props) ->
    parse_connack_props(Props,
                        #{assigned_client_id => undefined,
                          session_expiry => undefined,
                          receive_max => undefined,
                          max_packet_size => undefined,
                          reason_string => undefined,
                          user_properties => []}, #{}).

parse_connack_props(<<>>, Acc, _Seen) ->
    {ok, Acc};
parse_connack_props(Bin, Acc, Seen) ->
    case decode_varint(Bin) of
        {ok, ?PROP_SESSION_EXPIRY, Rest} ->
            case take_seen(?PROP_SESSION_EXPIRY, Seen) of
                error -> {error, malformed_connack_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<V:32/big, Tail/binary>> ->
                            parse_connack_props(Tail, Acc#{session_expiry => V}, Seen1);
                        _ -> {error, truncated_connack}
                    end
            end;
        {ok, ?PROP_ASSIGNED_CLIENT_ID, Rest} ->
            case take_seen(?PROP_ASSIGNED_CLIENT_ID, Seen) of
                error -> {error, malformed_connack_properties};
                {ok, Seen1} ->
                    case take_prop_utf8(Rest) of
                        {ok, Id, Tail} ->
                            parse_connack_props(Tail, Acc#{assigned_client_id => Id}, Seen1);
                        {error, _} -> {error, truncated_connack}
                    end
            end;
        {ok, ?PROP_RECV_MAXIMUM, Rest} ->
            case take_seen(?PROP_RECV_MAXIMUM, Seen) of
                error -> {error, malformed_connack_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<V:16/big, Tail/binary>> ->
                            parse_connack_props(Tail, Acc#{receive_max => V}, Seen1);
                        _ -> {error, truncated_connack}
                    end
            end;
        {ok, ?PROP_MAX_PACKET_SIZE, Rest} ->
            case take_seen(?PROP_MAX_PACKET_SIZE, Seen) of
                error -> {error, malformed_connack_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<V:32/big, Tail/binary>> ->
                            parse_connack_props(Tail, Acc#{max_packet_size => V}, Seen1);
                        _ -> {error, truncated_connack}
                    end
            end;
        {ok, ?PROP_REASON_STRING, Rest} ->
            case take_seen(?PROP_REASON_STRING, Seen) of
                error -> {error, malformed_connack_properties};
                {ok, Seen1} ->
                    case take_prop_utf8(Rest) of
                        {ok, S, Tail} ->
                            parse_connack_props(Tail, Acc#{reason_string => S}, Seen1);
                        {error, _} -> {error, truncated_connack}
                    end
            end;
        {ok, ?PROP_USER_PROPERTY, Rest} ->
            case take_prop_utf8(Rest) of
                {ok, K, Rest1} ->
                    case take_prop_utf8(Rest1) of
                        {ok, V, Tail} ->
                            Got = maps:get(user_properties, Acc),
                            case length(Got) >= ?MAX_V5_USER_PROPS of
                                true -> {error, malformed_connack_properties};
                                false ->
                                    parse_connack_props(
                                      Tail, Acc#{user_properties => Got ++ [{K, V}]}, Seen)
                            end;
                        {error, _} -> {error, truncated_connack}
                    end;
                {error, _} -> {error, truncated_connack}
            end;
        {ok, ?ALIAS_MAXIMUM_PROPERTY_ID, Rest} ->
            case take_seen(?ALIAS_MAXIMUM_PROPERTY_ID, Seen) of
                error -> {error, malformed_connack_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<V:16/big, Tail/binary>> ->
                            parse_connack_props(Tail, Acc#{alias_max => V}, Seen1);
                        _ -> {error, truncated_connack}
                    end
            end;
        {ok, Id, Rest} ->
            case skip_property(Id, Rest) of
                {ok, Tail} -> parse_connack_props(Tail, Acc, Seen);
                {error, _} = Err -> Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @private Encode a variable-byte integer (property and CONNACK
%% property lengths). Mirrors `encode_remaining_length/1' but accepts
%% the full 32-bit range the varint form carries.
encode_varint(N) when is_integer(N), N >= 0, N =< 16#0FFFFFFF ->
    encode_varint_out(N, <<>>).

encode_varint_out(0, <<>>) -> <<0>>;
encode_varint_out(0, Acc) -> Acc;
encode_varint_out(N, Acc) ->
    Digit = N rem 128,
    Rest = N div 128,
    if Rest > 0 -> encode_varint_out(Rest, <<Acc/binary, (Digit bor 16#80)>>);
       true -> <<Acc/binary, Digit>>
    end.

%% @doc Map a kernel bind return code to an MQTT 3.1.1 CONNACK return
%% code. The kernel answers with MQTT 5 reason codes (e.g. 16#86 bad
%% user name or password), but 3.1.1 only defines 0..5 and reserves the
%% rest, so reason codes fold into their closest 3.1.1 equivalent.
-spec connack_return_code(0..255) -> 0..5.
connack_return_code(RC) when is_integer(RC), RC >= 0, RC =< 5 -> RC;
connack_return_code(16#84) -> 1;   %% unsupported protocol version
connack_return_code(16#85) -> 2;   %% client identifier not valid
connack_return_code(16#86) -> 4;   %% bad user name or password
connack_return_code(16#87) -> 5;   %% not authorized
connack_return_code(16#8A) -> 5;   %% banned
connack_return_code(_) -> 3.       %% server unavailable, busy or over quota

%% @doc Decode an MQTT SUBSCRIBE payload (packet id + filter list).
%%
%% Takes the {@code payload} slice from {@code decode_packet/1}.
%% Each subscription is a {@code {Filter, QoS}} pair; binaries reference
%% the input (no copying). This is the 3.1.1 form (protocol level 4):
%% strict validation, whole-packet errors, bytes identical to before.
-spec decode_subscribe(binary()) -> {ok, subscribe_map()} | {error, term()}.
decode_subscribe(Bin) ->
    decode_subscribe(Bin, 4).

%% @doc Decode an MQTT SUBSCRIBE payload for the given protocol level
%% (X1-03: 4 or 5).
%%
%% Level 4 behaves exactly like the previous {@link decode_subscribe/1}.
%% Level 5 parses the property section (`PacketId | PropsLen | Props |
%% filters'). It extracts the subscription identifier (property 11,
%% 0 when absent). It then reads one options byte per filter (bits 0-1
%% QoS, bit 2 no-local, bit 3 retain-as-published, bits 4-5 retain
%% handling). The options byte rides through even when reserved bits
%% are set. The kernel fails only that filter with 16#8F.
%% Structural truncation fails the whole packet.
%% The identifier is packet-wide: the specification carries one
%% subscription-identifier property per SUBSCRIBE packet, so one value
%% applies to every filter in the packet.
-spec decode_subscribe(binary(), 4 | 5) -> {ok, subscribe_map()} | {error, term()}.
decode_subscribe(<<PacketId:16/big, Rest/binary>>, 4) when PacketId =/= 0 ->
    case decode_sub_list(Rest, []) of
        {ok, []} ->
            {error, empty_subscribe};
        {ok, Subs} ->
            {ok, #{packet_id => PacketId, subscriptions => Subs}};
        {error, _} = Err ->
            Err
    end;
decode_subscribe(<<PacketId:16/big, Rest/binary>>, 5) when PacketId =/= 0 ->
    case decode_varint(Rest) of
        {ok, PropLen, Rest1} when PropLen =< ?MAX_V5_SUB_PROPS_LEN ->
            case byte_size(Rest1) < PropLen of
                true ->
                    {error, truncated_subscribe};
                false ->
                    <<Props:PropLen/binary, Tail/binary>> = Rest1,
                    case parse_subscribe_props(Props) of
                        {ok, SubId} ->
                            case decode_sub_list_v5(Tail, []) of
                                {ok, []} ->
                                    {error, empty_subscribe};
                                {ok, Subs} ->
                                    {ok, #{packet_id => PacketId,
                                            subscriptions => Subs,
                                            sub_id => SubId}};
                                {error, _} = Err ->
                                    Err
                            end;
                        {error, _} = Err ->
                            Err
                    end
            end;
        _ ->
            {error, malformed_subscribe}
    end;
decode_subscribe(_, _) ->
    {error, malformed_subscribe}.

%% @private Parse a v5 SUBSCRIBE property block, returning the packet-wide
%% subscription identifier (0 when absent). A zero identifier, a duplicate
%% identifier or an over-maximum value fails the packet closed; user
%% properties are length-checked and skipped (bounded by
%% `MAX_V5_USER_PROPS'); other known properties are skipped by length.
parse_subscribe_props(Props) ->
    parse_subscribe_props(Props, undefined, 0).

parse_subscribe_props(<<>>, undefined, _) ->
    {ok, 0};
parse_subscribe_props(<<>>, {ok, SubId}, _) ->
    {ok, SubId};
parse_subscribe_props(Bin, Seen, UserCount) ->
    case decode_varint(Bin) of
        {ok, ?PROP_SUB_ID, Rest} ->
            case Seen of
                undefined ->
                    case decode_varint(Rest) of
                        {ok, 0, _} ->
                            {error, malformed_subscribe};
                        {ok, SubId, Tail} when SubId >= 1, SubId =< ?MAX_SUB_ID ->
                            parse_subscribe_props(Tail, {ok, SubId}, UserCount);
                        _ ->
                            {error, malformed_subscribe}
                    end;
                _ ->
                    {error, malformed_subscribe}
            end;
        {ok, ?PROP_USER_PROPERTY, Rest} ->
            case UserCount >= ?MAX_V5_USER_PROPS of
                true ->
                    {error, malformed_subscribe};
                false ->
                    case take_prop_utf8(Rest) of
                        {ok, _, Rest1} ->
                            case take_prop_utf8(Rest1) of
                                {ok, _, Tail} ->
                                    parse_subscribe_props(Tail, Seen, UserCount + 1);
                                {error, _} ->
                                    {error, truncated_subscribe}
                            end;
                        {error, _} ->
                            {error, truncated_subscribe}
                    end
            end;
        {ok, Id, Rest} ->
            case skip_property(Id, Rest) of
                {ok, Tail} ->
                    parse_subscribe_props(Tail, Seen, UserCount);
                {error, _} = Err ->
                    case Err of
                        {error, {unknown_property, _}} ->
                            {error, malformed_subscribe};
                        _ ->
                            Err
                    end
            end;
        {error, _} ->
            {error, malformed_subscribe}
    end.

%% @private Decode a v5 filter list: `FilterLen | Filter | Opts' per
%% entry. FilterLen 0 is accepted structurally (the kernel fails that
%% filter with 16#8F); the options byte rides through unvalidated so one
%% bad byte never fails the whole packet.
decode_sub_list_v5(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_sub_list_v5(<<FilterLen:16/big, Rest/binary>>, Acc) ->
    case Rest of
        <<Filter:FilterLen/binary, Opts:8, Tail/binary>> ->
            decode_sub_list_v5(Tail, [{Filter, Opts} | Acc]);
        _ ->
            {error, truncated_subscribe}
    end;
decode_sub_list_v5(_, _) ->
    {error, malformed_subscribe}.

%% @doc Decode one v5 subscription-options byte into its fields.
%% Returns `{ok, {QoS, NoLocal, Rap, RetainHandling}}' or `error' when
%% reserved bits are set, QoS > 2 or retain handling > 2 (fail closed:
%% the caller fails only that filter).
-spec decode_subscribe_opts(0..255) ->
    {ok, {0..2, boolean(), boolean(), 0..2}} | {error, term()}.
decode_subscribe_opts(Opts) when is_integer(Opts), Opts >= 0, Opts =< 255 ->
    case Opts band 16#C0 of
        0 ->
            QoS = Opts band 16#03,
            RH = (Opts band 16#30) bsr 4,
            case QoS =< 2 andalso RH =< 2 of
                true ->
                    {ok, {QoS, (Opts band 16#04) =/= 0,
                          (Opts band 16#08) =/= 0, RH}};
                false ->
                    {error, {invalid_subscribe_opts, Opts}}
            end;
        _ ->
            {error, {invalid_subscribe_opts, Opts}}
    end.

%% @doc Encode one v5 subscription-options byte from its fields.
-spec encode_subscribe_opts(0..2, boolean(), boolean(), 0..2) -> 0..255.
encode_subscribe_opts(QoS, NoLocal, Rap, RH)
  when (QoS =:= 0 orelse QoS =:= 1 orelse QoS =:= 2),
       is_boolean(NoLocal), is_boolean(Rap),
       (RH =:= 0 orelse RH =:= 1 orelse RH =:= 2) ->
    (QoS band 16#03)
    bor (case NoLocal of true -> 16#04; false -> 0 end)
    bor (case Rap of true -> 16#08; false -> 0 end)
    bor (RH bsl 4).

%% @doc Encode an MQTT SUBACK packet from a packet id and granted codes.
%%
%% Each code is a granted QoS (0..2) or 16#80 (failure). The Remaining
%% Length uses the variable-byte form: multi-filter subscribes grant
%% more than 125 codes, where a single raw byte would set the
%% continuation bit (or overflow) and desynchronise the reader.
-spec encode_suback(1..65535, [0..2 | 16#80]) -> binary().
encode_suback(PacketId, Codes)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535, is_list(Codes) ->
    ok = validate_suback_codes(Codes),
    Body = <<PacketId:16/big, (list_to_binary(Codes))/binary>>,
    RL = encode_remaining_length(byte_size(Body)),
    <<16#90, RL/binary, Body/binary>>.

%% @doc Encode an MQTT 5 SUBACK packet (X1-03, v5 subscribers only).
%% Wire form: `SUBACK | Remaining | PacketId:16be | PropsLen:varint |
%% Props | Codes'. Codes ride unmapped (granted QoS 0-2, 16#80
%% unspecified, 16#87 not authorized, 16#8F filter invalid, 16#97 quota
%% exceeded). Props carries the reason string (property 28, omitted when
%% empty) plus user properties (property 38, omitted when empty); the
%% broker never invents a reason string, so success SUBACKs carry empty
%% properties. The caller must gate on the negotiated protocol level and
%% use {@link encode_suback/2} for 3.1.1 peers.
-spec encode_suback_v5(1..65535, [0..255], map()) -> binary().
encode_suback_v5(PacketId, Codes, Opts)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535,
       is_list(Codes), is_map(Opts) ->
    ok = validate_suback_v5_codes(Codes),
    Props = encode_suback_v5_props(Opts),
    true = (byte_size(Props) =< ?MAX_V5_SUB_PROPS_LEN) orelse erlang:error(badarg),
    PropLen = encode_varint(byte_size(Props)),
    Body = <<PacketId:16/big, PropLen/binary, Props/binary,
             (list_to_binary(Codes))/binary>>,
    RL = encode_remaining_length(byte_size(Body)),
    <<16#90, RL/binary, Body/binary>>.

%% @doc Decode an MQTT 5 SUBACK body back into its fields (EUnit vectors
%% and any future v5 client path; the edge accept path only encodes).
-spec decode_suback_v5(binary()) -> {ok, suback_v5_map()} | {error, term()}.
decode_suback_v5(<<PacketId:16/big, Rest/binary>>) when PacketId =/= 0 ->
    case decode_varint(Rest) of
        {ok, PropLen, Rest1} ->
            case byte_size(Rest1) < PropLen of
                true ->
                    {error, truncated_suback};
                false ->
                    <<Props:PropLen/binary, Codes/binary>> = Rest1,
                    case Codes of
                        <<>> ->
                            {error, empty_suback};
                        _ ->
                            case parse_suback_props(Props) of
                                {ok, Parsed} ->
                                    {ok, Parsed#{packet_id => PacketId,
                                                 codes => binary_to_list(Codes)}};
                                {error, _} = Err ->
                                    Err
                            end
                    end
            end;
        {error, _} ->
            {error, malformed_suback}
    end;
decode_suback_v5(_) ->
    {error, malformed_suback}.

%% @doc Decode an MQTT PUBLISH payload with its fixed-header flags.
%%
%% Flags is the low nibble of the fixed header byte (DUP | QoS(2) |
%% RETAIN). Returns topic, packet id (0 when QoS 0), flags and the raw
%% zero-copy application payload. This is the 3.1.1 form (protocol
%% level 4): the wire carries no properties, an empty topic is
%% malformed, and the alias is always reported absent
%% (`alias => 0, alias_present => false').
-spec decode_publish(binary(), 0..15) -> {ok, publish_map()} | {error, term()}.
decode_publish(Payload, Flags) ->
    decode_publish(Payload, Flags, 4).

%% @doc Decode an MQTT PUBLISH payload for the given protocol level
%% (B4-05: 4 or 5).
%%
%% Level 4 behaves exactly like {@link decode_publish/2}. Level 5
%% parses the MQTT 5 property section (`Remaining | properties |
%% payload') and extracts the Topic Alias (property 35): absent means
%% "no alias carried" (`alias => 0, alias_present => false'), while an
%% explicit on-wire alias 0 (`alias => 0, alias_present => true') is a
%% protocol error the kernel rejects with DISCONNECT 0x94. An empty
%% topic is accepted only when the alias property is present
%% (alias-by-reference); otherwise the topic must be non-empty and
%% wildcard-free as before.
-spec decode_publish(binary(), 0..15, 4 | 5) -> {ok, publish_map()} | {error, term()}.
decode_publish(Payload, Flags, Level)
  when is_binary(Payload), is_integer(Flags), Flags >= 0, Flags =< 15,
       (Level =:= 4 orelse Level =:= 5) ->
    Qos = (Flags band 16#06) bsr 1,
    Dup = (Flags band 16#08) =/= 0,
    Retain = (Flags band 16#01) =/= 0,
    case Qos of
        Q when Q > 2 ->
            {error, {invalid_publish_qos, Q}};
        _ when Level =:= 4 ->
            case Payload of
                <<TopicLen:16/big, Rest/binary>> when TopicLen > 0 ->
                    case Rest of
                        <<Topic:TopicLen/binary, Tail/binary>> ->
                            case has_wildcard(Topic) of
                                true -> {error, invalid_publish_topic};
                                false -> decode_publish_tail(Qos, Topic, Dup, Retain, Tail)
                            end;
                        _ ->
                            {error, truncated_publish}
                    end;
                _ ->
                    {error, malformed_publish_topic}
            end;
        _ ->
            decode_publish_v5(Payload, Qos, Dup, Retain)
    end.

has_wildcard(Topic) ->
    case binary:match(Topic, [<<"+">>, <<"#">>]) of
        nomatch -> false;
        _ -> true
    end.

%% @doc Encode an outgoing MQTT PUBLISH packet (DUP = 0, RETAIN = 0).
-spec encode_publish(binary(), 0..65535, 0..2, binary()) -> binary().
encode_publish(Topic, PacketId, QoS, Payload) ->
    encode_publish(Topic, PacketId, QoS, false, false, Payload).

%% @doc Encode an outgoing MQTT PUBLISH packet with full flag control.
-spec encode_publish(binary(), 0..65535, 0..2, boolean(), boolean(), binary()) -> binary().
encode_publish(Topic, PacketId, QoS, Retain, Dup, Payload)
  when is_binary(Topic), byte_size(Topic) >= 1, byte_size(Topic) =< ?MAX_TOPIC_LEN,
       is_integer(PacketId), PacketId >= 0, PacketId =< 65535,
       (QoS =:= 0 orelse QoS =:= 1 orelse QoS =:= 2),
       is_boolean(Retain), is_boolean(Dup), is_binary(Payload) ->
    ok = validate_publish_id(QoS, PacketId),
    Header = case QoS of
        0 -> <<(byte_size(Topic)):16/big, Topic/binary>>;
        _ -> <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big>>
    end,
    Body = <<Header/binary, Payload/binary>>,
    Flags = (case Dup of true -> 16#08; false -> 0 end)
        bor (QoS bsl 1)
        bor (case Retain of true -> 16#01; false -> 0 end),
    RL = encode_remaining_length(byte_size(Body)),
    <<3:4, Flags:4, RL/binary, Body/binary>>.

%% @doc Encode an outgoing MQTT PUBLISH packet with a Topic Alias (B4-05).
%% Alias 0 encodes exactly like {@link encode_publish/6} (no property, so
%% 3.1.1 peers see no change); a nonzero alias appends the alias property
%% (`35:u8 | value:u16be' framed by {@link encode_topic_alias/1}) after a
%% one-byte property length between the packet id and the payload, so a
%% socket subscriber can observe the kernel-assigned alias. The caller
%% must ensure `alias_in_range(Alias, Max)'; 0 means "full topic, no alias".
-spec encode_publish(binary(), 0..65535, 0..2, boolean(), boolean(), binary(), 0..65535) -> binary().
encode_publish(Topic, PacketId, QoS, Retain, Dup, Payload, 0) ->
    encode_publish(Topic, PacketId, QoS, Retain, Dup, Payload);
encode_publish(Topic, PacketId, QoS, Retain, Dup, Payload, Alias)
  when is_binary(Topic), byte_size(Topic) >= 1, byte_size(Topic) =< ?MAX_TOPIC_LEN,
       is_integer(PacketId), PacketId >= 0, PacketId =< 65535,
       (QoS =:= 0 orelse QoS =:= 1 orelse QoS =:= 2),
       is_boolean(Retain), is_boolean(Dup), is_binary(Payload),
       is_integer(Alias), Alias >= 1, Alias =< ?MAX_TOPIC_ALIAS ->
    ok = validate_publish_id(QoS, PacketId),
    AliasBin = encode_topic_alias(Alias),
    Props = <<?TOPIC_ALIAS_PROPERTY_ID:8, AliasBin/binary>>,
    Header = case QoS of
        0 -> <<(byte_size(Topic)):16/big, Topic/binary, (byte_size(Props)):8, Props/binary>>;
        _ -> <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big,
               (byte_size(Props)):8, Props/binary>>
    end,
    Body = <<Header/binary, Payload/binary>>,
    Flags = (case Dup of true -> 16#08; false -> 0 end)
        bor (QoS bsl 1)
        bor (case Retain of true -> 16#01; false -> 0 end),
    RL = encode_remaining_length(byte_size(Body)),
    <<3:4, Flags:4, RL/binary, Body/binary>>.

%% @private Validate v5 SUBACK codes (granted QoS plus the documented
%% refusals). Anything else is a caller bug (never a half packet).
validate_suback_v5_codes([]) -> erlang:error(badarg);
validate_suback_v5_codes(Codes) when is_list(Codes) ->
    case lists:all(fun(C) ->
        C =:= 0 orelse C =:= 1 orelse C =:= 2 orelse
        C =:= 16#80 orelse C =:= ?SUBACK_RC_NOT_AUTHORIZED orelse
        C =:= ?SUBACK_RC_FILTER_INVALID orelse
        C =:= ?SUBACK_RC_QUOTA_EXCEEDED orelse C =:= 16#83
    end, Codes) of
        true -> ok;
        false -> erlang:error(badarg)
    end.

%% @private Encode a v5 SUBACK property block (reason string + user
%% properties, both omitted when empty so success SUBACKs stay small).
encode_suback_v5_props(Opts) ->
    Reason = maps:get(reason_string, Opts, <<>>),
    Users = maps:get(user_properties, Opts, []),
    RBin = case Reason of
        <<>> -> <<>>;
        S when is_binary(S), byte_size(S) >= 1,
               byte_size(S) =< ?MAX_V5_PROP_STRING_LEN ->
            <<?PROP_REASON_STRING:8, (byte_size(S)):16/big, S/binary>>;
        _ -> erlang:error(badarg)
    end,
    UBin = case Users of
        [] -> <<>>;
        Pairs when is_list(Pairs) ->
            true = (length(Pairs) =< ?MAX_V5_USER_PROPS) orelse erlang:error(badarg),
            lists:foldl(
              fun({K, V}, Acc) when is_binary(K), is_binary(V),
                                     byte_size(K) >= 1,
                                     byte_size(K) =< ?MAX_V5_PROP_STRING_LEN,
                                     byte_size(V) =< ?MAX_V5_PROP_STRING_LEN ->
                      <<Acc/binary, ?PROP_USER_PROPERTY:8,
                        (byte_size(K)):16/big, K/binary,
                        (byte_size(V)):16/big, V/binary>>;
                 (_, _) -> erlang:error(badarg)
              end, <<>>, Pairs);
        _ -> erlang:error(badarg)
    end,
    <<RBin/binary, UBin/binary>>.

%% @private Parse a v5 SUBACK property block (reason string once, user
%% properties accumulated, others skipped by length).
parse_suback_props(Props) ->
    parse_suback_props(Props, #{reason_string => <<>>, user_properties => []}, #{}).

parse_suback_props(<<>>, Acc, _Seen) ->
    {ok, Acc};
parse_suback_props(Bin, Acc, Seen) ->
    case decode_varint(Bin) of
        {ok, ?PROP_REASON_STRING, Rest} ->
            case maps:is_key(?PROP_REASON_STRING, Seen) of
                true -> {error, malformed_suback};
                false ->
                    case take_prop_utf8(Rest) of
                        {ok, S, Tail} ->
                            parse_suback_props(Tail, Acc#{reason_string => S},
                                               Seen#{?PROP_REASON_STRING => true});
                        {error, _} -> {error, truncated_suback}
                    end
            end;
        {ok, ?PROP_USER_PROPERTY, Rest} ->
            case take_prop_utf8(Rest) of
                {ok, K, Rest1} ->
                    case take_prop_utf8(Rest1) of
                        {ok, V, Tail} ->
                            Got = maps:get(user_properties, Acc),
                            case length(Got) >= ?MAX_V5_USER_PROPS of
                                true -> {error, malformed_suback};
                                false ->
                                    parse_suback_props(
                                      Tail, Acc#{user_properties => Got ++ [{K, V}]}, Seen)
                            end;
                        {error, _} -> {error, truncated_suback}
                    end;
                {error, _} -> {error, truncated_suback}
            end;
        {ok, Id, Rest} ->
            case skip_property(Id, Rest) of
                {ok, Tail} -> parse_suback_props(Tail, Acc, Seen);
                {error, _} -> {error, malformed_suback}
            end;
        {error, _} ->
            {error, malformed_suback}
    end.

%% @doc Encode an outgoing MQTT 5 PUBLISH packet with a subscription
%% identifier (0 = no identifier). The packet always has the property
%% length, because MQTT 5 requires it. The caller must use this function
%% only for a socket that negotiated protocol level 5.
-spec encode_publish_v5(binary(), 0..65535, 0..2, boolean(), boolean(),
                        binary(), 0..65535, 0..268435455) -> binary().
encode_publish_v5(Topic, PacketId, QoS, Retain, Dup, Payload, Alias, SubId) ->
    encode_publish_v5_full(Topic, PacketId, QoS, Retain, Dup, Payload,
                           Alias, SubId, 0, 0, []).

%% @doc Encode an outgoing MQTT 5 PUBLISH packet with subscription
%% identifier plus forwarded v5 properties (X1-03 deliveries).
%% `Format' is 0|1, `Expiry' a u32 message-expiry interval, `Users' a
%% bounded `[{Key, Value}]' user-property list. Empty properties
%% encode as a property length of zero; a
%% version-4 peer never reaches here (the caller gates on the
%% negotiated level). Over-bound inputs fail with `badarg' (fail
%% closed: the caller falls back to the property-less form).
-spec encode_publish_v5_full(binary(), 0..65535, 0..2, boolean(), boolean(),
                             binary(), 0..65535, 0..268435455,
                             0..1, 0..4294967295, [{binary(), binary()}]) -> binary().
encode_publish_v5_full(Topic, PacketId, QoS, Retain, Dup, Payload,
                       Alias, SubId, Format, Expiry, Users)
  when is_binary(Topic), byte_size(Topic) >= 1, byte_size(Topic) =< ?MAX_TOPIC_LEN,
       is_integer(PacketId), PacketId >= 0, PacketId =< 65535,
       (QoS =:= 0 orelse QoS =:= 1 orelse QoS =:= 2),
       is_boolean(Retain), is_boolean(Dup), is_binary(Payload),
       is_integer(Alias), Alias >= 0, Alias =< ?MAX_TOPIC_ALIAS,
       is_integer(SubId), SubId >= 0, SubId =< ?MAX_SUB_ID,
       (Format =:= 0 orelse Format =:= 1),
       is_integer(Expiry), Expiry >= 0, Expiry =< 16#FFFFFFFF,
       is_list(Users) ->
    ok = validate_publish_id(QoS, PacketId),
    true = (length(Users) =< ?MAX_V5_USER_PROPS) orelse erlang:error(badarg),
    %% One delivery carries at most one identifier.
    IdCount = case SubId of 0 -> 0; _ -> 1 end,
    true = (IdCount =< ?MAX_V5_SUB_IDS) orelse erlang:error(badarg),
    AliasProps = case Alias of
        0 -> <<>>;
        _ -> <<?TOPIC_ALIAS_PROPERTY_ID:8, (encode_topic_alias(Alias))/binary>>
    end,
    SubProps = case SubId of
        0 -> <<>>;
        _ -> <<?PROP_SUB_ID:8, (encode_varint(SubId))/binary>>
    end,
    FormatProps = case Format of
        0 -> <<>>;
        1 -> <<?PROP_PAYLOAD_FORMAT:8, 1:8>>
    end,
    ExpiryProps = case Expiry of
        0 -> <<>>;
        _ -> <<?PROP_MSG_EXPIRY:8, Expiry:32/big>>
    end,
    UserProps = lists:foldl(
      fun({K, V}, Acc) when is_binary(K), is_binary(V),
                             byte_size(K) >= 1,
                             byte_size(K) =< ?MAX_V5_PROP_STRING_LEN,
                             byte_size(V) =< ?MAX_V5_PROP_STRING_LEN ->
              <<Acc/binary, ?PROP_USER_PROPERTY:8,
                (byte_size(K)):16/big, K/binary,
                (byte_size(V)):16/big, V/binary>>;
         (_, _) -> erlang:error(badarg)
      end, <<>>, Users),
    Props = <<AliasProps/binary, SubProps/binary, FormatProps/binary,
              ExpiryProps/binary, UserProps/binary>>,
    %% MQTT 5 requires the property length in each PUBLISH. An empty
    %% property section is one zero byte.
    PropLen = encode_varint(byte_size(Props)),
    Header = case QoS of
        0 -> <<(byte_size(Topic)):16/big, Topic/binary, PropLen/binary, Props/binary>>;
        _ -> <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big,
               PropLen/binary, Props/binary>>
    end,
    Body = <<Header/binary, Payload/binary>>,
    Flags = (case Dup of true -> 16#08; false -> 0 end)
        bor (QoS bsl 1)
        bor (case Retain of true -> 16#01; false -> 0 end),
    RL = encode_remaining_length(byte_size(Body)),
    <<3:4, Flags:4, RL/binary, Body/binary>>.

%% @doc Decode an MQTT 5 DISCONNECT body (X1-03): reason code plus
%% properties (reason string + user properties, bounded). Empty body
%% means normal disconnection (code 0, no properties). A truncated
%% property section fails closed.
-spec decode_disconnect_v5(binary()) -> {ok, disconnect_v5_map()} | {error, term()}.
decode_disconnect_v5(<<>>) ->
    {ok, #{reason_code => 0, reason_string => <<>>, user_properties => []}};
decode_disconnect_v5(<<RC:8>>) ->
    {ok, #{reason_code => RC, reason_string => <<>>, user_properties => []}};
decode_disconnect_v5(<<RC:8, Rest/binary>>) ->
    case decode_varint(Rest) of
        {ok, PropLen, Rest1} ->
            case byte_size(Rest1) < PropLen of
                true ->
                    {error, truncated_disconnect};
                false ->
                    <<Props:PropLen/binary, Tail/binary>> = Rest1,
                    case Tail of
                        <<>> ->
                            case parse_disconnect_props(Props) of
                                {ok, Parsed} ->
                                    {ok, Parsed#{reason_code => RC}};
                                {error, _} = Err ->
                                    Err
                            end;
                        _ ->
                            {error, trailing_disconnect_bytes}
                    end
            end;
        {error, _} ->
            {error, malformed_disconnect}
    end;
decode_disconnect_v5(_) ->
    {error, malformed_disconnect}.

%% @private Parse a v5 DISCONNECT property block (reason string once,
%% user properties accumulated, others skipped by length). The broker
%% never invents a reason string; an absent one decodes as empty.
parse_disconnect_props(Props) ->
    parse_disconnect_props(Props, #{reason_string => <<>>, user_properties => []}, #{}).

parse_disconnect_props(<<>>, Acc, _Seen) ->
    {ok, Acc};
parse_disconnect_props(Bin, Acc, Seen) ->
    case decode_varint(Bin) of
        {ok, ?PROP_REASON_STRING, Rest} ->
            case maps:is_key(?PROP_REASON_STRING, Seen) of
                true -> {error, malformed_disconnect};
                false ->
                    case take_prop_utf8(Rest) of
                        {ok, S, Tail} ->
                            parse_disconnect_props(Tail, Acc#{reason_string => S},
                                                   Seen#{?PROP_REASON_STRING => true});
                        {error, _} -> {error, truncated_disconnect}
                    end
            end;
        {ok, ?PROP_USER_PROPERTY, Rest} ->
            case take_prop_utf8(Rest) of
                {ok, K, Rest1} ->
                    case take_prop_utf8(Rest1) of
                        {ok, V, Tail} ->
                            Got = maps:get(user_properties, Acc),
                            case length(Got) >= ?MAX_V5_USER_PROPS of
                                true -> {error, malformed_disconnect};
                                false ->
                                    parse_disconnect_props(
                                      Tail, Acc#{user_properties => Got ++ [{K, V}]}, Seen)
                            end;
                        {error, _} -> {error, truncated_disconnect}
                    end;
                {error, _} -> {error, truncated_disconnect}
            end;
        {ok, Id, Rest} ->
            case skip_property(Id, Rest) of
                {ok, Tail} -> parse_disconnect_props(Tail, Acc, Seen);
                {error, _} -> {error, malformed_disconnect}
            end;
        {error, _} ->
            {error, malformed_disconnect}
    end.

%% @doc Encode an MQTT 5 DISCONNECT packet (X1-03). Code 0 with empty
%% properties encodes as the 2-byte 3.1.1 shape (no reason, no
%% properties) so version-4 peers see no change; any other code or a
%% non-empty reason string carries the reason plus a property block.
%% The broker never invents a reason string: callers pass `<<>>' when
%% there is nothing to say and the property is omitted.
-spec encode_disconnect_v5(0..255, binary()) -> binary().
encode_disconnect_v5(RC, Reason) ->
    encode_disconnect_v5(RC, Reason, []).

%% @doc Encode an MQTT 5 DISCONNECT packet with user properties.
-spec encode_disconnect_v5(0..255, binary(), [{binary(), binary()}]) -> binary().
encode_disconnect_v5(0, <<>>, []) ->
    <<16#E0, 16#00>>;
encode_disconnect_v5(0, <<>>, Users) when is_list(Users), Users =/= [] ->
    Props = encode_disconnect_props(<<>>, Users),
    PropLen = encode_varint(byte_size(Props)),
    Body = <<0:8, PropLen/binary, Props/binary>>,
    RL = encode_remaining_length(byte_size(Body)),
    <<16#E0, RL/binary, Body/binary>>;
encode_disconnect_v5(RC, Reason, Users)
  when is_integer(RC), RC >= 0, RC =< 255, is_binary(Reason), is_list(Users) ->
    Props = encode_disconnect_props(Reason, Users),
    PropLen = encode_varint(byte_size(Props)),
    Body = <<RC:8, PropLen/binary, Props/binary>>,
    RL = encode_remaining_length(byte_size(Body)),
    <<16#E0, RL/binary, Body/binary>>.

%% @private Encode a DISCONNECT property block (reason string omitted
%% when empty, user properties bounded).
encode_disconnect_props(<<>>, []) -> <<>>;
encode_disconnect_props(Reason, Users) ->
    RBin = case Reason of
        <<>> -> <<>>;
        S when is_binary(S), byte_size(S) >= 1,
               byte_size(S) =< ?MAX_V5_PROP_STRING_LEN ->
            <<?PROP_REASON_STRING:8, (byte_size(S)):16/big, S/binary>>;
        _ -> erlang:error(badarg)
    end,
    UBin = case Users of
        [] -> <<>>;
        Pairs when is_list(Pairs) ->
            true = (length(Pairs) =< ?MAX_V5_USER_PROPS) orelse erlang:error(badarg),
            lists:foldl(
              fun({K, V}, Acc) when is_binary(K), is_binary(V),
                                     byte_size(K) >= 1,
                                     byte_size(K) =< ?MAX_V5_PROP_STRING_LEN,
                                     byte_size(V) =< ?MAX_V5_PROP_STRING_LEN ->
                      <<Acc/binary, ?PROP_USER_PROPERTY:8,
                        (byte_size(K)):16/big, K/binary,
                        (byte_size(V)):16/big, V/binary>>;
                 (_, _) -> erlang:error(badarg)
              end, <<>>, Pairs);
        _ -> erlang:error(badarg)
    end,
    <<RBin/binary, UBin/binary>>.

%% @doc Encode an MQTT PUBACK packet for a QoS 1 delivery.
-spec encode_puback(1..65535) -> binary().
encode_puback(PacketId)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535 ->
    <<16#40, 16#02, PacketId:16/big>>.

%% @doc Encode an MQTT PUBREC packet for a QoS 2 exchange (D1-01).
-spec encode_pubrec(1..65535) -> binary().
encode_pubrec(PacketId)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535 ->
    <<16#50, 16#02, PacketId:16/big>>.

%% @doc Encode an MQTT PUBREC packet carrying a reason code (B4-05: 0x94
%% Topic Alias Invalid on an alias reject). RC 0 encodes exactly like
%% {@link encode_pubrec/1}; a nonzero RC appends the MQTT 5 reason code
%% so the publisher observes the rejection instead of a bare PUBREC.
-spec encode_pubrec(1..65535, 0..255) -> binary().
encode_pubrec(PacketId, 0) ->
    encode_pubrec(PacketId);
encode_pubrec(PacketId, RC)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535,
       is_integer(RC), RC >= 0, RC =< 255 ->
    <<16#50, 16#03, PacketId:16/big, RC:8>>.

%% @doc Encode an MQTT PUBREL packet for a QoS 2 exchange (D1-01).
%% Fixed-header flags are 0010 per MQTT 3.1.1 §3.6.1; there is no DUP bit.
-spec encode_pubrel(1..65535) -> binary().
encode_pubrel(PacketId)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535 ->
    <<16#62, 16#02, PacketId:16/big>>.

%% @doc Encode an MQTT PUBCOMP packet for a QoS 2 exchange (D1-01).
-spec encode_pubcomp(1..65535) -> binary().
encode_pubcomp(PacketId)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535 ->
    <<16#70, 16#02, PacketId:16/big>>.

%% @doc Encode a Topic Alias Maximum property value (u16, big-endian).
-spec encode_alias_maximum(0..65535) -> binary().
encode_alias_maximum(Max)
  when is_integer(Max), Max >= 0, Max =< ?MAX_TOPIC_ALIAS ->
    <<Max:16/big>>.

%% @doc Decode a Topic Alias Maximum property value.
-spec decode_alias_maximum(binary()) -> {ok, 0..65535} | {error, term()}.
decode_alias_maximum(<<Max:16/big>>) ->
    {ok, Max};
decode_alias_maximum(_) ->
    {error, malformed_alias_maximum}.

%% @doc Encode a PUBLISH Topic Alias property value (u16, big-endian).
-spec encode_topic_alias(0..65535) -> binary().
encode_topic_alias(Alias)
  when is_integer(Alias), Alias >= 0, Alias =< ?MAX_TOPIC_ALIAS ->
    <<Alias:16/big>>.

%% @doc Decode a PUBLISH Topic Alias property value.
-spec decode_topic_alias(binary()) -> {ok, 0..65535} | {error, term()}.
decode_topic_alias(<<Alias:16/big>>) ->
    {ok, Alias};
decode_topic_alias(_) ->
    {error, malformed_topic_alias}.

%% @doc True when Alias may be used under Max (1..=Max, Max > 0).
-spec alias_in_range(0..65535, 0..65535) -> boolean().
alias_in_range(0, _) -> false;
alias_in_range(_, 0) -> false;
alias_in_range(Alias, Max)
  when is_integer(Alias), is_integer(Max) ->
    Alias =< Max.

%% @doc Map a 4-bit packet type code to its atom name.
-spec packet_type_atom(0..15) -> atom().
packet_type_atom(1) -> connect;
packet_type_atom(2) -> connack;
packet_type_atom(3) -> publish;
packet_type_atom(4) -> puback;
packet_type_atom(5) -> pubrec;
packet_type_atom(6) -> pubrel;
packet_type_atom(7) -> pubcomp;
packet_type_atom(8) -> subscribe;
packet_type_atom(9) -> suback;
packet_type_atom(10) -> unsubscribe;
packet_type_atom(11) -> unsuback;
packet_type_atom(12) -> pingreq;
packet_type_atom(13) -> pingresp;
packet_type_atom(14) -> disconnect;
packet_type_atom(N) -> N.

%% @doc Map a packet type atom back to its 4-bit code.
-spec packet_type_code(atom() | 0..15) -> 0..15.
packet_type_code(connect) -> 1;
packet_type_code(connack) -> 2;
packet_type_code(publish) -> 3;
packet_type_code(puback) -> 4;
packet_type_code(pubrec) -> 5;
packet_type_code(pubrel) -> 6;
packet_type_code(pubcomp) -> 7;
packet_type_code(subscribe) -> 8;
packet_type_code(suback) -> 9;
packet_type_code(unsubscribe) -> 10;
packet_type_code(unsuback) -> 11;
packet_type_code(pingreq) -> 12;
packet_type_code(pingresp) -> 13;
packet_type_code(disconnect) -> 14;
packet_type_code(N) when is_integer(N), N >= 0, N =< 15 -> N.

%%=============================================================%% Internal helpers
%%=============================================================
is_valid_type(Type) when Type >= 1, Type =< 14 -> true;
is_valid_type(_) -> false.

%% Flag rules per MQTT 3.1.1 §2.2.2 (only the six edge-handled types plus
%% generic safety for the rest).
validate_flags(1, 0) -> ok;   %% CONNECT reserved flags must be 0
validate_flags(1, F) -> {error, {invalid_flags, connect, F}};
validate_flags(3, Flags) ->   %% PUBLISH: DUP|QoS(2)|RETAIN
    Qos = (Flags band 16#06) bsr 1,
    if Qos =< 2 -> ok; true -> {error, {invalid_flags, publish, Flags}} end;
validate_flags(4, 0) -> ok;   %% PUBACK
validate_flags(4, F) -> {error, {invalid_flags, puback, F}};
validate_flags(8, 2) -> ok;   %% SUBSCRIBE reserved flags must be 0010
validate_flags(8, F) -> {error, {invalid_flags, subscribe, F}};
validate_flags(10, 2) -> ok;  %% UNSUBSCRIBE reserved flags must be 0010
validate_flags(10, F) -> {error, {invalid_flags, unsubscribe, F}};
validate_flags(12, 0) -> ok;  %% PINGREQ
validate_flags(12, F) -> {error, {invalid_flags, pingreq, F}};
validate_flags(13, 0) -> ok;  %% PINGRESP
validate_flags(13, F) -> {error, {invalid_flags, pingresp, F}};
validate_flags(14, 0) -> ok;  %% DISCONNECT
validate_flags(14, F) -> {error, {invalid_flags, disconnect, F}};
%% For packet types outside the Sprint-1 edge set, accept any flags here;
%% the Rust core performs full validation.
validate_flags(Type, _Flags) when Type >= 1, Type =< 14 -> ok;
validate_flags(Type, Flags) -> {error, {invalid_flags, Type, Flags}}.

%% @private Decode the SUBSCRIBE filter list (accumulator reversed).
decode_sub_list(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_sub_list(<<FilterLen:16/big, Rest/binary>>, Acc) when FilterLen > 0 ->
    case Rest of
        <<Filter:FilterLen/binary, QoS:8, Tail/binary>> when QoS =< 2 ->
            decode_sub_list(Tail, [{Filter, QoS} | Acc]);
        <<_:FilterLen/binary, QoS:8, _/binary>> ->
            {error, {invalid_subscribe_qos, QoS}};
        _ ->
            {error, truncated_subscribe}
    end;
decode_sub_list(_, _) ->
    {error, malformed_subscribe}.

validate_suback_codes([]) -> ok;
validate_suback_codes([16#80 | Rest]) -> validate_suback_codes(Rest);
validate_suback_codes([C | Rest]) when C >= 0, C =< 2 -> validate_suback_codes(Rest);
validate_suback_codes(_) -> erlang:error(badarg).

decode_publish_tail(0, Topic, Dup, Retain, AppPayload) ->
    %% The 3.1.1 wire carries no alias property, so the edge always
    %% reports the alias absent here.
    {ok, #{topic => Topic,
           packet_id => 0,
           qos => 0,
           retain => Retain,
           dup => Dup,
           alias => 0,
           alias_present => false,
           payload => AppPayload}};
decode_publish_tail(Qos, Topic, Dup, Retain, Tail) ->
    case Tail of
        <<PacketId:16/big, AppPayload/binary>> when PacketId =/= 0 ->
            {ok, #{topic => Topic,
                   packet_id => PacketId,
                   qos => Qos,
                   retain => Retain,
                   dup => Dup,
                   alias => 0,
                   alias_present => false,
                   payload => AppPayload}};
        _ ->
            {error, malformed_publish_packet_id}
    end.

%% @private Decode a level-5 PUBLISH body: topic, packet id, MQTT 5
%% properties (Topic Alias 35 extracted), then the application payload.
decode_publish_v5(<<TopicLen:16/big, Rest/binary>>, Qos, Dup, Retain) ->
    case Rest of
        <<Topic:TopicLen/binary, Tail/binary>> ->
            case TopicLen > 0 andalso has_wildcard(Topic) of
                true ->
                    {error, invalid_publish_topic};
                false ->
                    decode_publish_v5_tail(Qos, Topic, TopicLen, Dup, Retain, Tail)
            end;
        _ ->
            {error, truncated_publish}
    end;
decode_publish_v5(_, _, _, _) ->
    {error, malformed_publish_topic}.

%% @private After the v5 topic: packet id (QoS > 0), then the property
%% section, then the payload.
decode_publish_v5_tail(Qos, Topic, TopicLen, Dup, Retain, Tail) ->
    case Qos of
        0 ->
            decode_publish_v5_props(Qos, 0, Topic, TopicLen, Dup, Retain, Tail);
        _ ->
            case Tail of
                <<PacketId:16/big, Rest/binary>> when PacketId =/= 0 ->
                    decode_publish_v5_props(Qos, PacketId, Topic, TopicLen,
                                            Dup, Retain, Rest);
                _ ->
                    {error, malformed_publish_packet_id}
            end
    end.

%% @private Parse the v5 property section and build the publish map.
%% X1-03 extracts the Topic Alias (35) plus payload-format (1),
%% message-expiry (2) and user properties (38, bounded); a
%% subscription identifier (11) from a client is a protocol error
%% (only the server sends it on delivery), failing the PUBLISH closed.
%% Inbound user properties ride into the map for the BrokerLink forward;
%% message-expiry and format ride along. The task scope is
%% decode-and-forward, so the edge forwards the expiry value without
%% enforcing it: no message is dropped on a timer the task never built.
decode_publish_v5_props(Qos, PacketId, Topic, TopicLen, Dup, Retain, Tail) ->
    case decode_varint(Tail) of
        {ok, PropLen, Rest} ->
            case byte_size(Rest) < PropLen of
                true ->
                    {error, truncated_publish};
                false ->
                    <<Props:PropLen/binary, AppPayload/binary>> = Rest,
                    case parse_publish_v5(Props) of
                        {ok, Alias, AliasPresent, Format, Expiry, Users} ->
                            case TopicLen =:= 0 andalso not AliasPresent of
                                true ->
                                    {error, malformed_publish_topic};
                                false ->
                                    {ok, #{topic => Topic,
                                           packet_id => PacketId,
                                           qos => Qos,
                                           retain => Retain,
                                           dup => Dup,
                                           alias => Alias,
                                           alias_present => AliasPresent,
                                           payload_format => Format,
                                           message_expiry => Expiry,
                                           user_properties => Users,
                                           sub_ids => [],
                                           payload => AppPayload}}
                            end;
                        {error, _} = Err ->
                            Err
                    end
            end;
        {error, _} = Err ->
            Err
    end.

%% @private Full v5 PUBLISH properties parse (inbound: alias + format +
%% expiry + user properties; subscription identifiers rejected).
parse_publish_v5(Props) ->
    parse_publish_v5(Props, undefined, undefined, undefined, []).

parse_publish_v5(<<>>, AliasSeen, FormatSeen, ExpirySeen, Users) ->
    {Alias, Present} = case AliasSeen of
        undefined -> {0, false};
        {ok, A} -> {A, true}
    end,
    Format = case FormatSeen of undefined -> 0; {ok, F} -> F end,
    Expiry = case ExpirySeen of undefined -> 0; {ok, E} -> E end,
    {ok, Alias, Present, Format, Expiry, Users};
parse_publish_v5(Bin, AliasSeen, FormatSeen, ExpirySeen, Users) ->
    case decode_varint(Bin) of
        {ok, 35, Rest} ->
            case Rest of
                <<Alias:16/big, Tail/binary>> ->
                    case AliasSeen of
                        undefined -> parse_publish_v5(Tail, {ok, Alias}, FormatSeen, ExpirySeen, Users);
                        _ -> {error, malformed_publish_properties}
                    end;
                _ ->
                    {error, truncated_publish}
            end;
        {ok, 1, Rest} ->
            case Rest of
                <<F:8, Tail/binary>> when F =:= 0; F =:= 1 ->
                    case FormatSeen of
                        undefined -> parse_publish_v5(Tail, AliasSeen, {ok, F}, ExpirySeen, Users);
                        _ -> {error, malformed_publish_properties}
                    end;
                <<_:8, _/binary>> ->
                    {error, malformed_publish_properties};
                _ ->
                    {error, truncated_publish}
            end;
        {ok, 2, Rest} ->
            case Rest of
                <<E:32/big, Tail/binary>> ->
                    case ExpirySeen of
                        undefined -> parse_publish_v5(Tail, AliasSeen, FormatSeen, {ok, E}, Users);
                        _ -> {error, malformed_publish_properties}
                    end;
                _ ->
                    {error, truncated_publish}
            end;
        {ok, 11, _Rest} ->
            %% Subscription identifiers flow server-to-client only; a
            %% client sending one fails closed (protocol error).
            {error, malformed_publish_properties};
        {ok, 38, Rest} ->
            case take_prop_utf8(Rest) of
                {ok, K, Rest1} ->
                    case take_prop_utf8(Rest1) of
                        {ok, V, Tail} ->
                            case length(Users) >= ?MAX_V5_USER_PROPS of
                                true -> {error, malformed_publish_properties};
                                false -> parse_publish_v5(Tail, AliasSeen, FormatSeen, ExpirySeen,
                                                          Users ++ [{K, V}])
                            end;
                        {error, _} -> {error, truncated_publish}
                    end;
                {error, _} -> {error, truncated_publish}
            end;
        {ok, Id, Rest} ->
            case skip_property(Id, Rest) of
                {ok, Tail} ->
                    parse_publish_v5(Tail, AliasSeen, FormatSeen, ExpirySeen, Users);
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            case Err of
                {error, truncated_connect} -> {error, truncated_publish};
                _ -> Err
            end
    end.

validate_publish_id(0, _) -> ok;
validate_publish_id(_, PacketId) when PacketId >= 1 -> ok;
validate_publish_id(_, _) -> erlang:error(badarg).

%% @private Defaults for the v5 CONNECT property fields. Level 4 has
%% no properties section so it always reports these (plus alias_max 0);
%% level 5 starts here and overrides each present property. Receive
%% Maximum defaults to 65535 (no flow-control limit announced), Maximum
%% Packet Size 0 means no limit announced, Session Expiry 0 means the
%% session ends at disconnect, Request Response Information defaults off
%% and Request Problem Information defaults on.
v5_connect_defaults(AliasMax) ->
    #{alias_max => AliasMax,
      session_expiry => 0,
      receive_max => 65535,
      max_packet_size => 0,
      req_resp_info => false,
      req_problem_info => true,
      auth_method => undefined,
      auth_data => undefined,
      user_properties => []}.

%% CONNECT flag rules per MQTT 3.1.1 §3.1.2.3 (shared by v5: the
%% flag byte is unchanged, only the properties section is new).
decode_connect_flags(Flags, Keepalive, Payload, Level, AliasMax) ->
    Username = (Flags band 16#80) =/= 0,
    Password = (Flags band 16#40) =/= 0,
    WillRetain = (Flags band 16#20) =/= 0,
    WillQos = (Flags band 16#18) bsr 3,
    WillFlag = (Flags band 16#04) =/= 0,
    CleanStart = (Flags band 16#02) =/= 0,
    Reserved = (Flags band 16#01) =/= 0,
    Valid = (not Reserved) andalso (WillQos =< 2)
        andalso (WillFlag orelse ((not WillRetain) andalso WillQos =:= 0))
        andalso ((not Password) orelse Username),
    case Valid of
        false ->
            {error, {invalid_connect_flags, Flags}};
        true ->
            case skip_connect_string(Payload) of
                {ok, ClientId, Rest} ->
                    case take_connect_options(Rest, WillFlag, Username, Password) of
                        {ok, User, Pass, WillTopic, WillPayload} ->
                            {ok, maps:merge(v5_connect_defaults(AliasMax),
                                            #{protocol_name => <<"MQTT">>,
                                              protocol_level => Level,
                                              clean_start => CleanStart,
                                              keepalive => Keepalive,
                                              client_id => ClientId,
                                              username_flag => Username,
                                              password_flag => Password,
                                              username => User,
                                              password => Pass,
                                              will_flag => WillFlag,
                                              will_qos => WillQos,
                                              will_retain => WillRetain,
                                              will_topic => WillTopic,
                                              will_payload => WillPayload})};
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end
    end.

%% @private Decode a level-5 CONNECT: properties (X1-01: session
%% expiry, receive maximum, maximum packet size, topic-alias maximum,
%% request-response/problem information, authentication method/data and
%% user properties) then the payload with its will-properties section.
%% A truncated property length, an overlong properties block (beyond
%% `MAX_CONNECT_PROPS_LEN') or a duplicate/malformed mandatory property
%% fails the CONNECT closed; trailing garbage after the payload fails it
%% the same way the 3.1.1 path does.
decode_connect_v5(Flags, Keepalive, Payload) ->
    case decode_varint(Payload) of
        {ok, PropLen, Rest} ->
            case PropLen > ?MAX_CONNECT_PROPS_LEN of
                true ->
                    {error, malformed_connect_properties};
                false ->
                    case byte_size(Rest) < PropLen of
                        true ->
                            {error, truncated_connect};
                        false ->
                            <<Props:PropLen/binary, Tail/binary>> = Rest,
                            case parse_connect_props(Props) of
                                {ok, Parsed} ->
                                    decode_connect_v5_tail(Flags, Keepalive, Parsed, Tail);
                                {error, _} = Err ->
                                    Err
                            end
                    end
            end;
        {error, _} = Err ->
            Err
    end.

%% @private After the v5 CONNECT properties: client id, will properties
%% plus will topic/payload when the will flag is set, then credentials.
%% The parsed v5 properties ride into the connect map for the bind; the
%% kernel owns their session semantics (X1-02), the edge only frames and
%% transports them.
decode_connect_v5_tail(Flags, Keepalive, Parsed, Tail) ->
    Username = (Flags band 16#80) =/= 0,
    Password = (Flags band 16#40) =/= 0,
    WillRetain = (Flags band 16#20) =/= 0,
    WillQos = (Flags band 16#18) bsr 3,
    WillFlag = (Flags band 16#04) =/= 0,
    CleanStart = (Flags band 16#02) =/= 0,
    Reserved = (Flags band 16#01) =/= 0,
    Valid = (not Reserved) andalso (WillQos =< 2)
        andalso (WillFlag orelse ((not WillRetain) andalso WillQos =:= 0))
        andalso ((not Password) orelse Username),
    case Valid of
        false ->
            {error, {invalid_connect_flags, Flags}};
        true ->
            case skip_connect_string(Tail) of
                {ok, ClientId, Rest} ->
                    case skip_will_properties(Rest, WillFlag) of
                        {ok, Rest1} ->
                            case take_connect_options(Rest1, WillFlag, Username, Password) of
                                {ok, User, Pass, WillTopic, WillPayload} ->
                                    {ok, (Parsed#{protocol_name => <<"MQTT">>,
                                                  protocol_level => 5,
                                                  clean_start => CleanStart,
                                                  keepalive => Keepalive,
                                                  client_id => ClientId,
                                                  username_flag => Username,
                                                  password_flag => Password,
                                                  username => User,
                                                  password => Pass,
                                                  will_flag => WillFlag,
                                                  will_qos => WillQos,
                                                  will_retain => WillRetain,
                                                  will_topic => WillTopic,
                                                  will_payload => WillPayload})};
                                {error, _} = Err ->
                                    Err
                            end;
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end
    end.

%% @private Skip the will-properties section (present only when the
%% will flag is set): a variable-byte length followed by that many
%% property bytes.
skip_will_properties(Bin, false) ->
    {ok, Bin};
skip_will_properties(Bin, true) ->
    case decode_varint(Bin) of
        {ok, Len, Rest} ->
            case byte_size(Rest) < Len of
                true -> {error, truncated_connect};
                false ->
                    <<_:Len/binary, Tail/binary>> = Rest,
                    {ok, Tail}
            end;
        {error, _} = Err ->
            Err
    end.

%% @private MQTT variable-byte integer (property lengths and ids):
%% up to 4 bytes, bit 7 is the continuation flag. Inside an already
%% framed packet a short input is malformed, never "more".
decode_varint(Bin) when is_binary(Bin) ->
    decode_varint(Bin, 0, 0).

decode_varint(<<>>, _, _) ->
    {error, truncated_connect};
decode_varint(<<Byte:8, Rest/binary>>, Value, Shift) when Shift < 28 ->
    Value1 = Value + ((Byte band 16#7F) bsl Shift),
    case Byte band 16#80 of
        0 ->
            {ok, Value1, Rest};
        _ ->
            decode_varint(Rest, Value1, Shift + 7)
    end;
decode_varint(_, _, _) ->
    {error, malformed_varint}.

%% @private Extract the v5 CONNECT properties (X1-01) from a
%% properties block. Returns the full property map merged over
%% {@link v5_connect_defaults/1}: absent means the default documented
%% there. A duplicate single-occurrence property, an out-of-range value
%% or a truncated value fails closed. Known-but-inapplicable properties
%% (valid identifiers the CONNECT path does not use) are length-checked
%% and skipped, never fatal; a totally unknown identifier fails closed
%% (its length is unknowable, so skipping would desynchronise the
%% packet).
%% TODO(parity): the specification's "ignore unknown properties" rule
%% for future property identifiers is open: without a length table the
%% edge cannot skip them, so it currently fails closed. Confirm whether
%% a future identifier registry or a kernel consult should decide.
parse_connect_props(Props) ->
    parse_connect_props(Props, v5_connect_defaults(0), #{}).

parse_connect_props(<<>>, Acc, _Seen) ->
    {ok, Acc};
parse_connect_props(Bin, Acc, Seen) ->
    case decode_varint(Bin) of
        {ok, ?PROP_SESSION_EXPIRY, Rest} ->
            case take_seen(?PROP_SESSION_EXPIRY, Seen) of
                error -> {error, malformed_connect_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<Expiry:32/big, Tail/binary>> ->
                            parse_connect_props(Tail, Acc#{session_expiry => Expiry}, Seen1);
                        _ ->
                            {error, truncated_connect}
                    end
            end;
        {ok, ?PROP_RECV_MAXIMUM, Rest} ->
            case take_seen(?PROP_RECV_MAXIMUM, Seen) of
                error -> {error, malformed_connect_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<RecvMax:16/big, Tail/binary>> ->
                            parse_connect_props(Tail, Acc#{receive_max => RecvMax}, Seen1);
                        _ ->
                            {error, truncated_connect}
                    end
            end;
        {ok, ?PROP_MAX_PACKET_SIZE, Rest} ->
            case take_seen(?PROP_MAX_PACKET_SIZE, Seen) of
                error -> {error, malformed_connect_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<MaxPkt:32/big, Tail/binary>> ->
                            parse_connect_props(Tail, Acc#{max_packet_size => MaxPkt}, Seen1);
                        _ ->
                            {error, truncated_connect}
                    end
            end;
        {ok, ?ALIAS_MAXIMUM_PROPERTY_ID, Rest} ->
            case take_seen(?ALIAS_MAXIMUM_PROPERTY_ID, Seen) of
                error -> {error, malformed_connect_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<Max:16/big, Tail/binary>> ->
                            parse_connect_props(Tail, Acc#{alias_max => Max}, Seen1);
                        _ ->
                            {error, truncated_connect}
                    end
            end;
        {ok, ?PROP_REQ_RESP_INFO, Rest} ->
            case take_seen(?PROP_REQ_RESP_INFO, Seen) of
                error -> {error, malformed_connect_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<1:8, Tail/binary>> ->
                            parse_connect_props(Tail, Acc#{req_resp_info => true}, Seen1);
                        <<0:8, Tail/binary>> ->
                            parse_connect_props(Tail, Acc#{req_resp_info => false}, Seen1);
                        _ ->
                            {error, malformed_connect_properties}
                    end
            end;
        {ok, ?PROP_REQ_PROBLEM_INFO, Rest} ->
            case take_seen(?PROP_REQ_PROBLEM_INFO, Seen) of
                error -> {error, malformed_connect_properties};
                {ok, Seen1} ->
                    case Rest of
                        <<1:8, Tail/binary>> ->
                            parse_connect_props(Tail, Acc#{req_problem_info => true}, Seen1);
                        <<0:8, Tail/binary>> ->
                            parse_connect_props(Tail, Acc#{req_problem_info => false}, Seen1);
                        _ ->
                            {error, malformed_connect_properties}
                    end
            end;
        {ok, ?PROP_AUTH_METHOD, Rest} ->
            case take_seen(?PROP_AUTH_METHOD, Seen) of
                error -> {error, malformed_connect_properties};
                {ok, Seen1} ->
                    case take_prop_utf8(Rest) of
                        {ok, Method, Tail} ->
                            parse_connect_props(Tail, Acc#{auth_method => Method}, Seen1);
                        {error, _} = Err ->
                            Err
                    end
            end;
        {ok, ?PROP_AUTH_DATA, Rest} ->
            case take_seen(?PROP_AUTH_DATA, Seen) of
                error -> {error, malformed_connect_properties};
                {ok, Seen1} ->
                    case take_prop_binary(Rest) of
                        {ok, Data, Tail} ->
                            parse_connect_props(Tail, Acc#{auth_data => Data}, Seen1);
                        {error, _} = Err ->
                            Err
                    end
            end;
        {ok, ?PROP_USER_PROPERTY, Rest} ->
            case take_prop_utf8(Rest) of
                {ok, Key, Rest1} ->
                    case take_prop_utf8(Rest1) of
                        {ok, Value, Tail} ->
                            Got = maps:get(user_properties, Acc),
                            case length(Got) >= ?MAX_V5_USER_PROPS of
                                true ->
                                    {error, malformed_connect_properties};
                                false ->
                                    parse_connect_props(
                                      Tail, Acc#{user_properties => Got ++ [{Key, Value}]}, Seen)
                            end;
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {ok, Id, Rest} ->
            case skip_property(Id, Rest) of
                {ok, Tail} ->
                    parse_connect_props(Tail, Acc, Seen);
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @private Mark a single-occurrence property seen; a second occurrence
%% is a protocol error (fail closed).
take_seen(Id, Seen) ->
    case maps:is_key(Id, Seen) of
        true -> error;
        false -> {ok, Seen#{Id => true}}
    end.

%% @private Take one length-prefixed UTF-8 string inside CONNECT
%% properties, enforcing the per-string bound. Returns the value plus
%% the tail; overlong or truncated fails the CONNECT closed.
take_prop_utf8(<<Len:16/big, Rest/binary>>) when Len =< ?MAX_V5_PROP_STRING_LEN ->
    case Rest of
        <<Str:Len/binary, Tail/binary>> -> {ok, Str, Tail};
        _ -> {error, truncated_connect}
    end;
take_prop_utf8(<<Len:16/big, _/binary>>) when Len > ?MAX_V5_PROP_STRING_LEN ->
    {error, malformed_connect_properties};
take_prop_utf8(_) ->
    {error, truncated_connect}.

%% @private Take one length-prefixed binary data value inside CONNECT
%% properties. The u16 length is the wire bound; truncation fails closed.
take_prop_binary(<<Len:16/big, Rest/binary>>) ->
    case Rest of
        <<Data:Len/binary, Tail/binary>> -> {ok, Data, Tail};
        _ -> {error, truncated_connect}
    end;
take_prop_binary(_) ->
    {error, truncated_connect}.

%% @private Skip one property value by its identifier. Lengths follow
%% MQTT 5.0 §2.2.2: u8, u16, u32, variable-byte integer, UTF-8 string,
%% binary data, or a string pair (user property 38). Unknown
%% identifiers fail closed: the edge closes instead of misframing the
%% properties block. Reason: a skipped length we do not know would
%% desynchronise the whole packet.
skip_property(1, <<_:8, Tail/binary>>) -> {ok, Tail};
skip_property(23, <<_:8, Tail/binary>>) -> {ok, Tail};
skip_property(25, <<_:8, Tail/binary>>) -> {ok, Tail};
skip_property(36, <<_:8, Tail/binary>>) -> {ok, Tail};
skip_property(37, <<_:8, Tail/binary>>) -> {ok, Tail};
skip_property(40, <<_:8, Tail/binary>>) -> {ok, Tail};
skip_property(41, <<_:8, Tail/binary>>) -> {ok, Tail};
skip_property(42, <<_:8, Tail/binary>>) -> {ok, Tail};
skip_property(19, <<_:16/big, Tail/binary>>) -> {ok, Tail};
skip_property(33, <<_:16/big, Tail/binary>>) -> {ok, Tail};
skip_property(34, <<_:16/big, Tail/binary>>) -> {ok, Tail};
skip_property(35, <<_:16/big, Tail/binary>>) -> {ok, Tail};
skip_property(2, <<_:32/big, Tail/binary>>) -> {ok, Tail};
skip_property(17, <<_:32/big, Tail/binary>>) -> {ok, Tail};
skip_property(39, <<_:32/big, Tail/binary>>) -> {ok, Tail};
skip_property(11, Bin) ->
    case decode_varint(Bin) of
        {ok, _, Tail} -> {ok, Tail};
        {error, _} = Err -> Err
    end;
skip_property(3, Bin) -> skip_utf8(Bin);
skip_property(8, Bin) -> skip_utf8(Bin);
skip_property(18, Bin) -> skip_utf8(Bin);
skip_property(28, Bin) -> skip_utf8(Bin);
skip_property(9, Bin) -> skip_binary_data(Bin);
skip_property(29, Bin) -> skip_binary_data(Bin);
skip_property(38, Bin) ->
    case skip_utf8(Bin) of
        {ok, Tail} -> skip_utf8(Tail);
        {error, _} = Err -> Err
    end;
%% TODO(parity): a totally unknown property identifier fails closed
%% here because its value length is unknowable: skipping would
%% desynchronise the properties block. The open question is whether the
%% specification's "ignore unknown properties" rule wants a future
%% identifier registry (or a kernel consult) instead of failing.
skip_property(Id, _) -> {error, {unknown_property, Id}}.

%% @private Skip one length-prefixed UTF-8 string inside properties.
skip_utf8(<<Len:16/big, Rest/binary>>) ->
    case byte_size(Rest) < Len of
        true -> {error, truncated_publish};
        false ->
            <<_:Len/binary, Tail/binary>> = Rest,
            {ok, Tail}
    end;
skip_utf8(_) ->
    {error, truncated_publish}.

%% @private Skip one length-prefixed binary data value in properties.
skip_binary_data(<<Len:16/big, Rest/binary>>) ->
    case byte_size(Rest) < Len of
        true -> {error, truncated_publish};
        false ->
            <<_:Len/binary, Tail/binary>> = Rest,
            {ok, Tail}
    end;
skip_binary_data(_) ->
    {error, truncated_publish}.

%% @private Skip one length-prefixed UTF-8 string, returning it plus the tail.
skip_connect_string(<<Len:16/big, Rest/binary>>) ->
    case Rest of
        <<Str:Len/binary, Tail/binary>> -> {ok, Str, Tail};
        _ -> {error, truncated_connect}
    end;
skip_connect_string(_) ->
    {error, truncated_connect}.

%% @private Take optional CONNECT fields, capturing the will topic and
%% message when the will flag is set (forwarded to the kernel in the
%% bind; the kernel owns the session and the publish decision) plus
%% username/password values. Username and password come back as
%% `undefined' when their flags are clear; will topic and payload come
%% back as `undefined' when the will flag is clear.
%% @private Take optional CONNECT fields, capturing username/password
%% plus the last-will topic/message for the kernel bind (MT-05). The
%% edge never validates the will topic itself; the kernel fails a bad
%% will closed at registration. Username, password, will topic and will
%% payload come back as `undefined` when their flags are clear.
take_connect_options(Rest, false, false, false) ->
    case Rest of
        <<>> -> {ok, undefined, undefined, undefined, undefined};
        _ -> {error, trailing_connect_bytes}
    end;
take_connect_options(Rest, WillFlag, Username, Password) ->
    case take_optional_string(Rest, WillFlag) of
        {ok, WillTopic, Rest1} ->
            case take_optional_string(Rest1, WillFlag) of
                {ok, WillPayload, Rest2} ->
                    case take_optional_string(Rest2, Username) of
                        {ok, User, Rest3} ->
                            case take_optional_string(Rest3, Password) of
                                {ok, Pass, <<>>} -> {ok, User, Pass, WillTopic, WillPayload};
                                {ok, _, _} -> {error, trailing_connect_bytes};
                                Err -> Err
                            end;
                        Err -> Err
                    end;
                Err -> Err
            end;
        Err -> Err
    end.

take_optional_string(Bin, false) -> {ok, undefined, Bin};
take_optional_string(Bin, true) ->
    case skip_connect_string(Bin) of
        {ok, Value, Tail} -> {ok, Value, Tail};
        Err -> Err
    end.

%% Remaining-length decoder: at most 4 bytes, bit 7 = continuation.
decode_rl(<<>>, _Value, _Count) ->
    {more, 1};
decode_rl(<<Byte, Rest/binary>>, Value, Count) ->
    Digit = Byte band 16#7F,
    Value1 = Value + Digit * (1 bsl (7 * Count)),
    case Byte band 16#80 of
        0 ->
            {ok, Value1, Count + 1};
        16#80 ->
            if
                Count >= 3 ->
                    %% Fourth byte still has the continuation bit set.
                    {error, malformed_remaining_length};
                true ->
                    case Rest of
                        <<>> -> {more, 1};
                        _ -> decode_rl(Rest, Value1, Count + 1)
                    end
            end
    end.

encode_rl(0, <<>>) -> <<0>>;
encode_rl(0, Acc) -> Acc;
encode_rl(N, Acc) ->
    Digit = N rem 128,
    Rest = N div 128,
    if
        Rest > 0 -> encode_rl(Rest, <<Acc/binary, (Digit bor 16#80)>>);
        true -> <<Acc/binary, Digit>>
    end.
