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
         connack_return_code/1,
          decode_subscribe/1,
          encode_suback/2,
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
                         alias_max := 0..65535}.
-type subscribe_map() :: #{packet_id := 1..65535,
                           subscriptions := [{binary(), 0..2}]}.
-type publish_map() :: #{topic := binary(),
                         packet_id := 0..65535,
                         qos := 0..2,
                         retain := boolean(),
                         dup := boolean(),
                         alias := 0..65535,
                         alias_present := boolean(),
                         payload := binary()}.

%%====================================================================
%% Public API
%%====================================================================

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
%% the input (no copying).
-spec decode_subscribe(binary()) -> {ok, subscribe_map()} | {error, term()}.
decode_subscribe(<<PacketId:16/big, Rest/binary>>) when PacketId =/= 0 ->
    case decode_sub_list(Rest, []) of
        {ok, []} ->
            {error, empty_subscribe};
        {ok, Subs} ->
            {ok, #{packet_id => PacketId, subscriptions => Subs}};
        {error, _} = Err ->
            Err
    end;
decode_subscribe(_) ->
    {error, malformed_subscribe}.

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

%%====================================================================
%% Internal helpers
%%====================================================================

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
decode_publish_v5_props(Qos, PacketId, Topic, TopicLen, Dup, Retain, Tail) ->
    case decode_varint(Tail) of
        {ok, PropLen, Rest} ->
            case byte_size(Rest) < PropLen of
                true ->
                    {error, truncated_publish};
                false ->
                    <<Props:PropLen/binary, AppPayload/binary>> = Rest,
                    case parse_publish_alias(Props) of
                        {ok, Alias, AliasPresent} ->
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
                                           payload => AppPayload}}
                            end;
                        {error, _} = Err ->
                            Err
                    end
            end;
        {error, _} = Err ->
            Err
    end.

validate_publish_id(0, _) -> ok;
validate_publish_id(_, PacketId) when PacketId >= 1 -> ok;
validate_publish_id(_, _) -> erlang:error(badarg).

%% CONNECT flag rules per MQTT 3.1.1 §3.1.2.3 (shared by v5: the
%% flag byte is unchanged, only the properties section is new).
decode_connect_flags(Flags, Keepalive, Payload) ->
    decode_connect_flags(Flags, Keepalive, Payload, 4, 0).

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
                            {ok, #{protocol_name => <<"MQTT">>,
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
                                   will_payload => WillPayload,
                                   alias_max => AliasMax}};
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end
    end.

%% @private Decode a level-5 CONNECT: properties (Topic Alias Maximum
%% extracted) then the payload with its will-properties section.
decode_connect_v5(Flags, Keepalive, Payload) ->
    case decode_varint(Payload) of
        {ok, PropLen, Rest} ->
            case byte_size(Rest) < PropLen of
                true ->
                    {error, truncated_connect};
                false ->
                    <<Props:PropLen/binary, Tail/binary>> = Rest,
                    case parse_connect_alias_max(Props) of
                        {ok, AliasMax} ->
                            decode_connect_v5_tail(Flags, Keepalive, AliasMax, Tail);
                        {error, _} = Err ->
                            Err
                    end
            end;
        {error, _} = Err ->
            Err
    end.

%% @private After the v5 CONNECT properties: client id, will properties
%% plus will topic/payload when the will flag is set, then credentials.
decode_connect_v5_tail(Flags, Keepalive, AliasMax, Tail) ->
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
                                    {ok, #{protocol_name => <<"MQTT">>,
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
                                           will_payload => WillPayload,
                                           alias_max => AliasMax}};
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

%% @private Extract the Topic Alias Maximum (property 34, u16) from a
%% CONNECT properties block. Absent means 0 (client accepts no
%% aliases). A duplicate or out-of-range value fails closed.
parse_connect_alias_max(Props) ->
    parse_connect_alias_max(Props, undefined).

parse_connect_alias_max(<<>>, undefined) ->
    {ok, 0};
parse_connect_alias_max(<<>>, {ok, Max}) ->
    {ok, Max};
parse_connect_alias_max(Bin, Seen) ->
    case decode_varint(Bin) of
        {ok, 34, Rest} ->
            case Rest of
                <<Max:16/big, Tail/binary>> ->
                    case Seen of
                        undefined -> parse_connect_alias_max(Tail, {ok, Max});
                        _ -> {error, malformed_connect_properties}
                    end;
                _ ->
                    {error, truncated_connect}
            end;
        {ok, Id, Rest} ->
            case skip_property(Id, Rest) of
                {ok, Tail} ->
                    parse_connect_alias_max(Tail, Seen);
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

%% @private Extract the Topic Alias (property 35, u16) from a PUBLISH
%% properties block. Returns `{ok, Alias, Present}': absent means
%% `{ok, 0, false}', an explicit on-wire 0 means `{ok, 0, true}'
%% (a protocol error the kernel rejects with DISCONNECT 0x94).
parse_publish_alias(Props) ->
    parse_publish_alias(Props, undefined).

parse_publish_alias(<<>>, undefined) ->
    {ok, 0, false};
parse_publish_alias(<<>>, {ok, Alias}) ->
    {ok, Alias, true};
parse_publish_alias(Bin, Seen) ->
    case decode_varint(Bin) of
        {ok, 35, Rest} ->
            case Rest of
                <<Alias:16/big, Tail/binary>> ->
                    case Seen of
                        undefined -> parse_publish_alias(Tail, {ok, Alias});
                        _ -> {error, malformed_publish_properties}
                    end;
                _ ->
                    {error, truncated_publish}
            end;
        {ok, Id, Rest} ->
            case skip_property(Id, Rest) of
                {ok, Tail} ->
                    parse_publish_alias(Tail, Seen);
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            case Err of
                {error, truncated_connect} -> {error, truncated_publish};
                _ -> Err
            end
    end.

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
