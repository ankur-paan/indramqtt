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
         packet_type_atom/1,
         packet_type_code/1]).

-define(MAX_REMAINING, 268435455).

-type packet_map() :: #{type := 1..14,
                        type_atom := atom(),
                        flags := 0..15,
                        remaining_length := non_neg_integer(),
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
