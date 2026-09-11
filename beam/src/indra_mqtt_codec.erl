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
         decode_subscribe/1,
         encode_suback/2,
         decode_publish/2,
         encode_publish/4,
         encode_publish/6,
         encode_puback/1,
         packet_type_atom/1,
         packet_type_code/1]).

-define(MAX_REMAINING, 268435455).
-define(MAX_TOPIC_LEN, 65535).

-type packet_map() :: #{type := 1..14,
                        type_atom := atom(),
                        flags := 0..15,
                        remaining_length := non_neg_integer(),
                        payload := binary()}.
-type connect_map() :: #{protocol_name := binary(),
                         protocol_level := 4,
                         clean_start := boolean(),
                         keepalive := 0..65535,
                         client_id := binary(),
                         username_flag := boolean(),
                         password_flag := boolean(),
                         will_flag := boolean(),
                         will_qos := 0..2,
                         will_retain := boolean()}.
-type subscribe_map() :: #{packet_id := 1..65535,
                           subscriptions := [{binary(), 0..2}]}.
-type publish_map() :: #{topic := binary(),
                         packet_id := 0..65535,
                         qos := 0..2,
                         retain := boolean(),
                         dup := boolean(),
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

%% @doc Decode an MQTT 3.1.1 CONNECT variable header + payload.
%%
%% Takes the zero-copy {@code payload} slice produced by
%% {@code decode_packet/1} for a CONNECT packet and extracts the
%% connection parameters the edge needs for the BrokerLink handshake.
%% All returned binaries reference the input (no copying).
-spec decode_connect(binary()) -> {ok, connect_map()} | {error, term()}.
decode_connect(<<NameLen:16/big, Rest/binary>>) ->
    case Rest of
        <<ProtoName:NameLen/binary, Level:8, Flags:8, Keepalive:16/big, Payload/binary>> ->
            case {ProtoName, Level} of
                {<<"MQTT">>, 4} ->
                    decode_connect_flags(Flags, Keepalive, Payload);
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
%% Each code is a granted QoS (0..2) or 16#80 (failure).
-spec encode_suback(1..65535, [0..2 | 16#80]) -> binary().
encode_suback(PacketId, Codes)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535, is_list(Codes) ->
    ok = validate_suback_codes(Codes),
    <<16#90, (2 + length(Codes)), PacketId:16/big, (list_to_binary(Codes))/binary>>.

%% @doc Decode an MQTT PUBLISH payload with its fixed-header flags.
%%
%% Flags is the low nibble of the fixed header byte (DUP | QoS(2) |
%% RETAIN). Returns topic, packet id (0 when QoS 0), flags and the raw
%% zero-copy application payload.
-spec decode_publish(binary(), 0..15) -> {ok, publish_map()} | {error, term()}.
decode_publish(Payload, Flags)
  when is_binary(Payload), is_integer(Flags), Flags >= 0, Flags =< 15 ->
    Qos = (Flags band 16#06) bsr 1,
    Dup = (Flags band 16#08) =/= 0,
    Retain = (Flags band 16#01) =/= 0,
    case Qos of
        Q when Q > 2 ->
            {error, {invalid_publish_qos, Q}};
        _ ->
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
            end
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

%% @doc Encode an MQTT PUBACK packet for a QoS 1 delivery.
-spec encode_puback(1..65535) -> binary().
encode_puback(PacketId)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535 ->
    <<16#40, 16#02, PacketId:16/big>>.

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
    {ok, #{topic => Topic,
           packet_id => 0,
           qos => 0,
           retain => Retain,
           dup => Dup,
           payload => AppPayload}};
decode_publish_tail(Qos, Topic, Dup, Retain, Tail) ->
    case Tail of
        <<PacketId:16/big, AppPayload/binary>> when PacketId =/= 0 ->
            {ok, #{topic => Topic,
                   packet_id => PacketId,
                   qos => Qos,
                   retain => Retain,
                   dup => Dup,
                   payload => AppPayload}};
        _ ->
            {error, malformed_publish_packet_id}
    end.

validate_publish_id(0, _) -> ok;
validate_publish_id(_, PacketId) when PacketId >= 1 -> ok;
validate_publish_id(_, _) -> erlang:error(badarg).

%% CONNECT flag rules per MQTT 3.1.1 §3.1.2.3.
decode_connect_flags(Flags, Keepalive, Payload) ->
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
                    case skip_connect_options(Rest, WillFlag, Username, Password) of
                        ok ->
                            {ok, #{protocol_name => <<"MQTT">>,
                                   protocol_level => 4,
                                   clean_start => CleanStart,
                                   keepalive => Keepalive,
                                   client_id => ClientId,
                                   username_flag => Username,
                                   password_flag => Password,
                                   will_flag => WillFlag,
                                   will_qos => WillQos,
                                   will_retain => WillRetain}};
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end
    end.

%% @private Skip one length-prefixed UTF-8 string, returning it plus the tail.
skip_connect_string(<<Len:16/big, Rest/binary>>) ->
    case Rest of
        <<Str:Len/binary, Tail/binary>> -> {ok, Str, Tail};
        _ -> {error, truncated_connect}
    end;
skip_connect_string(_) ->
    {error, truncated_connect}.

%% @private Skip optional CONNECT fields (will topic/message, username,
%% password) to prove the packet is well-formed; content is session
%% business and stays opaque to the edge.
skip_connect_options(Rest, false, false, false) ->
    case Rest of
        <<>> -> ok;
        _ -> {error, trailing_connect_bytes}
    end;
skip_connect_options(Rest, WillFlag, Username, Password) ->
    case skip_optional_string(Rest, WillFlag) of
        {ok, Rest1} ->
            case skip_optional_string(Rest1, WillFlag) of
                {ok, Rest2} ->
                    case skip_optional_string(Rest2, Username) of
                        {ok, Rest3} ->
                            case skip_optional_string(Rest3, Password) of
                                {ok, <<>>} -> ok;
                                {ok, _} -> {error, trailing_connect_bytes};
                                Err -> Err
                            end;
                        Err -> Err
                    end;
                Err -> Err
            end;
        Err -> Err
    end.

skip_optional_string(Bin, false) -> {ok, Bin};
skip_optional_string(Bin, true) ->
    case skip_connect_string(Bin) of
        {ok, _, Tail} -> {ok, Tail};
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
