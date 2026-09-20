%% @doc IndraMQTT BrokerLink IPC client (BEAM edge side).
%%
%% Connection != Session: this module owns the *connection* to the Rust
%% BrokerLink core over a binary IPC channel (TCP loopback or UDS).
%% Framing matches {@code crates/brokerlink/src/header.rs} exactly:
%%
%% <pre>
%%   0                   1                   2                   3
%%   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |      'B'      |      'L'      |    Version    |     Flags     |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |             Opcode            |                               |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
%%  |                          ConnId (64-bit BE)                   |
%%  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |                               |                               |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
%%  |                       SequenceNo (64-bit BE)                  |
%%  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |                               |            MetaLen            |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |                        PayloadLen (32-bit BE)                 |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |                    Meta (MetaLen bytes) ...                   |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |                  Payload (PayloadLen bytes) ...               |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% </pre>
%%
%% Total fixed header: 28 bytes.
-module(indra_brokerlink).

-behaviour(gen_server).

%% Public framing API.
-export([encode_frame/5,
         decode_frame/1,
         opcode_to_int/1,
         int_to_opcode/1]).

%% BrokerLink metadata contracts (Sprint 2: connection handshake).
-export([encode_bind_meta/3,
         encode_bind_meta/4,
         decode_bind_meta/1,
         encode_session_binding_meta/3,
         decode_session_binding_meta/1]).

%% BrokerLink metadata contracts (Sprint 3: messaging loop).
-export([encode_subscribe_meta/3,
         decode_subscribe_meta/1,
         encode_suback_meta/2,
         decode_suback_meta/1,
         encode_publish_meta/5,
         decode_publish_meta/1,
         encode_puback_meta/2,
         decode_puback_meta/1,
         encode_unbind_meta/1,
         decode_unbind_meta/1]).

%% BrokerLink metadata contract (W0-24/W0-25: kernel -> edge ConnClose).
%% Empty metadata and empty payload; the header conn_id identifies the
%% edge connection to close.
-export([encode_connclose_meta/0,
         decode_connclose_meta/1]).

%% gen_server lifecycle + IPC API.
-export([start_link/0,
         start_link/1,
         stop/1,
         ping/2,
         send/6,
         brokerlink_sock_opts/0]).

%% gen_server callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(MAGIC_0, 16#42).
-define(MAGIC_1, 16#4C).
-define(VERSION, 1).
-define(FLAGS, 0).
-define(HEADER_LEN, 28).
-define(MAX_META_LEN, 65535).
-define(MAX_PAYLOAD_LEN, 4294967295).

-define(DEFAULT_HOST, "127.0.0.1").
-define(DEFAULT_PORT, 18883).

-type opcode() :: ping | pong
                | bind_connection | session_binding | unbind_connection
                | publish_in | publish_out
                | puback_in | puback_out
                | pubrec_in | pubrec_out
                | pubrel_in | pubrel_out
                | pubcomp_in | pubcomp_out
                 | subscribe_in | suback_out
                 | unsubscribe_in | unsuback_out
                 | disconnect_in | conn_close
                 | non_neg_integer().
-type header_map() :: #{version := 0..255,
                        flags := 0..255,
                        opcode := non_neg_integer(),
                        conn_id := non_neg_integer(),
                        seq_no := non_neg_integer(),
                        meta_len := non_neg_integer(),
                        payload_len := non_neg_integer()}.
-type start_opt() :: {transport, tcp | uds}
                   | {host, string()}
                   | {port, inet:port_number()}
                   | {path, string()}
                   | {reconnect, boolean()}
                   | {backoff_base_ms, pos_integer()}
                   | {backoff_max_ms, pos_integer()}.

%%====================================================================
%% Framing API
%%====================================================================

%% @doc Encode one BrokerLink frame.
%%
%% Opcode may be an atom (e.g. {@code ping}) or a raw 16-bit integer.
%% MetaBin and PayloadBin must be binaries. Returns the complete binary
%% (header + meta + payload). Raises {@code error(badarg)} when lengths
%% exceed the wire limits (MetaLen > 65535).
-spec encode_frame(opcode(), non_neg_integer(), non_neg_integer(),
                   binary(), binary()) -> binary().
encode_frame(Opcode, ConnId, SeqNo, MetaBin, PayloadBin)
  when is_binary(MetaBin), is_binary(PayloadBin),
       is_integer(ConnId), ConnId >= 0, ConnId =< 16#FFFFFFFFFFFFFFFF,
       is_integer(SeqNo), SeqNo >= 0, SeqNo =< 16#FFFFFFFFFFFFFFFF ->
    OpInt = opcode_to_int(Opcode),
    MetaLen = byte_size(MetaBin),
    PayloadLen = byte_size(PayloadBin),
    true = (MetaLen =< ?MAX_META_LEN) orelse erlang:error(badarg),
    true = (PayloadLen =< ?MAX_PAYLOAD_LEN) orelse erlang:error(badarg),
    <<?MAGIC_0, ?MAGIC_1, ?VERSION, ?FLAGS,
      OpInt:16/big,
      ConnId:64/big,
      SeqNo:64/big,
      MetaLen:16/big,
      PayloadLen:32/big,
      MetaBin/binary,
      PayloadBin/binary>>.

%% @doc Decode one frame from the front of Binary.
%%
%% Returns {@code {ok, Header, Meta, Payload, Rest}} on success,
%% {@code {more, NeedBytes}} when more wire bytes are required, or
%% {@code {error, Reason}} for corrupt data (bad magic, bad version,
%% unknown opcode).
-spec decode_frame(binary()) ->
    {ok, header_map(), binary(), binary(), binary()}
  | {more, pos_integer()}
  | {error, term()}.
decode_frame(Bin) when is_binary(Bin) ->
    Size = byte_size(Bin),
    if
        Size < ?HEADER_LEN ->
            {more, ?HEADER_LEN - Size};
        true ->
            <<M0, M1, Ver, Flags,
              OpRaw:16/big,
              ConnId:64/big,
              SeqNo:64/big,
              MetaLen:16/big,
              PayloadLen:32/big,
              _/binary>> = Bin,
            if
                M0 =/= ?MAGIC_0 orelse M1 =/= ?MAGIC_1 ->
                    {error, {invalid_magic, M0, M1}};
                Ver =/= ?VERSION ->
                    {error, {unsupported_version, Ver}};
                true ->
                    case is_known_opcode(OpRaw) of
                        false ->
                            {error, {unknown_opcode, OpRaw}};
                        true ->
                            Total = ?HEADER_LEN + MetaLen + PayloadLen,
                            if
                                Size < Total ->
                                    {more, Total - Size};
                                true ->
                                    <<_H:?HEADER_LEN/binary,
                                      Meta:MetaLen/binary,
                                      Payload:PayloadLen/binary,
                                      Rest/binary>> = Bin,
                                    Header = #{version => Ver,
                                               flags => Flags,
                                               opcode => OpRaw,
                                               conn_id => ConnId,
                                               seq_no => SeqNo,
                                               meta_len => MetaLen,
                                               payload_len => PayloadLen},
                                    {ok, Header, Meta, Payload, Rest}
                            end
                    end
            end
    end.

%% @doc Map an opcode atom (or raw int passthrough) to its wire integer.
-spec opcode_to_int(opcode()) -> non_neg_integer().
opcode_to_int(ping) -> 16#0001;
opcode_to_int(pong) -> 16#0002;
opcode_to_int(bind_connection) -> 16#0010;
opcode_to_int(session_binding) -> 16#0011;
opcode_to_int(unbind_connection) -> 16#0012;
opcode_to_int(publish_in) -> 16#0020;
opcode_to_int(publish_out) -> 16#0021;
opcode_to_int(puback_in) -> 16#0022;
opcode_to_int(puback_out) -> 16#0023;
opcode_to_int(pubrec_in) -> 16#0024;
opcode_to_int(pubrec_out) -> 16#0025;
opcode_to_int(pubrel_in) -> 16#0026;
opcode_to_int(pubrel_out) -> 16#0027;
opcode_to_int(pubcomp_in) -> 16#0028;
opcode_to_int(pubcomp_out) -> 16#0029;
opcode_to_int(subscribe_in) -> 16#0030;
opcode_to_int(suback_out) -> 16#0031;
opcode_to_int(unsubscribe_in) -> 16#0032;
opcode_to_int(unsuback_out) -> 16#0033;
opcode_to_int(disconnect_in) -> 16#0040;
opcode_to_int(conn_close) -> 16#0041;
opcode_to_int(N) when is_integer(N), N >= 0, N =< 16#FFFF -> N.

%% @doc Map a wire integer to its opcode atom (unknown ints pass through).
-spec int_to_opcode(non_neg_integer()) -> opcode().
int_to_opcode(16#0001) -> ping;
int_to_opcode(16#0002) -> pong;
int_to_opcode(16#0010) -> bind_connection;
int_to_opcode(16#0011) -> session_binding;
int_to_opcode(16#0012) -> unbind_connection;
int_to_opcode(16#0020) -> publish_in;
int_to_opcode(16#0021) -> publish_out;
int_to_opcode(16#0022) -> puback_in;
int_to_opcode(16#0023) -> puback_out;
int_to_opcode(16#0024) -> pubrec_in;
int_to_opcode(16#0025) -> pubrec_out;
int_to_opcode(16#0026) -> pubrel_in;
int_to_opcode(16#0027) -> pubrel_out;
int_to_opcode(16#0028) -> pubcomp_in;
int_to_opcode(16#0029) -> pubcomp_out;
int_to_opcode(16#0030) -> subscribe_in;
int_to_opcode(16#0031) -> suback_out;
int_to_opcode(16#0032) -> unsubscribe_in;
int_to_opcode(16#0033) -> unsuback_out;
int_to_opcode(16#0040) -> disconnect_in;
int_to_opcode(16#0041) -> conn_close;
int_to_opcode(N) when is_integer(N) -> N.

is_known_opcode(16#0001) -> true;
is_known_opcode(16#0002) -> true;
is_known_opcode(16#0010) -> true;
is_known_opcode(16#0011) -> true;
is_known_opcode(16#0012) -> true;
is_known_opcode(16#0020) -> true;
is_known_opcode(16#0021) -> true;
is_known_opcode(16#0022) -> true;
is_known_opcode(16#0023) -> true;
is_known_opcode(16#0024) -> true;
is_known_opcode(16#0025) -> true;
is_known_opcode(16#0026) -> true;
is_known_opcode(16#0027) -> true;
is_known_opcode(16#0028) -> true;
is_known_opcode(16#0029) -> true;
is_known_opcode(16#0030) -> true;
is_known_opcode(16#0031) -> true;
is_known_opcode(16#0032) -> true;
is_known_opcode(16#0033) -> true;
is_known_opcode(16#0040) -> true;
is_known_opcode(16#0041) -> true;
is_known_opcode(_) -> false.

%%====================================================================
%% BrokerLink metadata contracts (Sprint 2: CONNECT -> CONNACK)
%%====================================================================
%%
%% These binary layouts are the canonical cross-language contract between
%% the BEAM edge (`indra_conn`) and the Rust core
%% (`crates/broker-node/src/main.rs::reply_for_frame`). Both sides
%% implement the identical layout; the Rust side mirrors these comments.
%%
%% BindConnection meta (Opcode 16#0010, BEAM -> Rust):
%% <pre>
%%   +------------------+----------------+-------+------------+-----------+
%%   | ClientIdLen:16be | ClientId bytes | Flags | Keepalive  | Creds...  |
%%   |                  |  (UTF-8)       |  :8   |  :16be     | (optional)|
%%   +------------------+----------------+-------+------------+-----------+
%% </pre>
%% Flags bit 0 = clean_start. All other bits are reserved and must be 0.
%% The optional trailing credentials section (present only for
%% authenticated connects) is:
%% {@code UserLen:16be | Username | PassLen:16be | Password}.
%% Anonymous connects omit it entirely (existing encodings are unchanged).
%%
%% SessionBinding meta (Opcode 16#0011, Rust -> BEAM):
%% <pre>
%%   +----------------+---------------+------------+
%%   | SessionId:64be | Present:8     | RC:8       |
%%   |                | (0 | 1)       | (0 = ok)   |
%%   +----------------+---------------+------------+
%% </pre>
%% RC mirrors the MQTT 3.1.1 CONNACK return code (0 = accepted,
%% 2 = identifier rejected).

-type bind_meta() :: #{client_id := binary(),
                       clean_start := boolean(),
                       keepalive := 0..65535,
                       username := binary() | undefined,
                       password := binary() | undefined}.
-type session_binding_meta() :: #{session_id := non_neg_integer(),
                                  session_present := boolean(),
                                  return_code := 0..255}.

%% @doc Encode BindConnection metadata for the given client parameters.
-spec encode_bind_meta(binary(), boolean(), 0..65535) -> binary().
encode_bind_meta(ClientId, CleanStart, Keepalive)
  when is_binary(ClientId), is_boolean(CleanStart),
       is_integer(Keepalive), Keepalive >= 0, Keepalive =< 65535 ->
    Flags = case CleanStart of true -> 1; false -> 0 end,
    IdLen = byte_size(ClientId),
    true = (IdLen =< 65535) orelse erlang:error(badarg),
    <<IdLen:16/big, ClientId/binary, Flags:8, Keepalive:16/big>>.

%% @doc Encode BindConnection metadata with credentials. Pass
%% `{undefined, undefined}` (or use {@link encode_bind_meta/3}) for
%% anonymous connects; any other combination appends the credentials
%% section. A username without a password is rejected.
-spec encode_bind_meta(binary(), boolean(), 0..65535,
                       {binary() | undefined, binary() | undefined}) -> binary().
encode_bind_meta(ClientId, CleanStart, Keepalive, {undefined, undefined}) ->
    encode_bind_meta(ClientId, CleanStart, Keepalive);
encode_bind_meta(ClientId, CleanStart, Keepalive, {User, Pass})
  when is_binary(User), is_binary(Pass) ->
    Base = encode_bind_meta(ClientId, CleanStart, Keepalive),
    true = (byte_size(User) =< 65535) orelse erlang:error(badarg),
    true = (byte_size(Pass) =< 65535) orelse erlang:error(badarg),
    <<Base/binary, (byte_size(User)):16/big, User/binary,
      (byte_size(Pass)):16/big, Pass/binary>>;
encode_bind_meta(_, _, _, _) ->
    erlang:error(badarg).

%% @doc Decode BindConnection metadata.
-spec decode_bind_meta(binary()) -> {ok, bind_meta()} | {error, term()}.
decode_bind_meta(<<IdLen:16/big, Rest/binary>>) ->
    case Rest of
        <<ClientId:IdLen/binary, Flags:8, Keepalive:16/big>> ->
            {ok, #{client_id => ClientId,
                   clean_start => (Flags band 16#01) =:= 16#01,
                   keepalive => Keepalive,
                   username => undefined,
                   password => undefined}};
        <<ClientId:IdLen/binary, Flags:8, Keepalive:16/big, Creds/binary>> ->
            case decode_bind_creds(Creds) of
                {ok, User, Pass} ->
                    {ok, #{client_id => ClientId,
                           clean_start => (Flags band 16#01) =:= 16#01,
                           keepalive => Keepalive,
                           username => User,
                           password => Pass}};
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, malformed_bind_meta}
    end;
decode_bind_meta(_) ->
    {error, malformed_bind_meta}.

decode_bind_creds(<<ULen:16/big, Rest/binary>>) ->
    case Rest of
        <<User:ULen/binary, PLen:16/big, PassRest/binary>> ->
            case PassRest of
                <<Pass:PLen/binary>> when PLen > 0 ->
                    {ok, User, Pass};
                _ ->
                    {error, malformed_bind_meta}
            end;
        _ ->
            {error, malformed_bind_meta}
    end;
decode_bind_creds(_) ->
    {error, malformed_bind_meta}.

%% @doc Encode SessionBinding metadata for the given session outcome.
-spec encode_session_binding_meta(non_neg_integer(), boolean(), 0..255) -> binary().
encode_session_binding_meta(SessionId, SessionPresent, ReturnCode)
  when is_integer(SessionId), SessionId >= 0, SessionId =< 16#FFFFFFFFFFFFFFFF,
       is_boolean(SessionPresent),
       is_integer(ReturnCode), ReturnCode >= 0, ReturnCode =< 255 ->
    Present = case SessionPresent of true -> 1; false -> 0 end,
    <<SessionId:64/big, Present:8, ReturnCode:8>>.

%% @doc Decode SessionBinding metadata.
-spec decode_session_binding_meta(binary()) ->
    {ok, session_binding_meta()} | {error, term()}.
decode_session_binding_meta(<<SessionId:64/big, Present:8, RC:8>>) ->
    case Present of
        0 -> {ok, #{session_id => SessionId,
                    session_present => false,
                    return_code => RC}};
        1 -> {ok, #{session_id => SessionId,
                    session_present => true,
                    return_code => RC}};
        _ -> {error, malformed_session_binding_meta}
    end;
decode_session_binding_meta(_) ->
    {error, malformed_session_binding_meta}.

%%====================================================================
%% BrokerLink metadata contracts (Sprint 3: messaging loop)
%%====================================================================
%%
%% Layouts mirrored by `crates/broker-node/src/main.rs`:
%%
%% SubscribeMeta (Opcode 16#0030, BEAM -> Rust):
%% {@code PacketId:16be | IdLen:16be | ClientId | N:16be |
%%  (FilterLen:16be | Filter | QoS:8) * N}
%%
%% SubAckMeta (Opcode 16#0031, Rust -> BEAM):
%% {@code PacketId:16be | GrantedCodes...} (one byte per subscription:
%% granted QoS 0..2 or 16#80 failure).
%%
%% PublishMeta (Opcodes 16#0020 / 16#0021, either direction):
%% {@code TopicLen:16be | Topic | PacketId:16be | QoS:8 | Retain:8 | Dup:8}
%% with Retain/Dup encoded 0 | 1. The application payload travels in the
%% frame payload section untouched.
%%
%% PubAckMeta (Opcodes 16#0023, Rust -> BEAM for QoS 1):
%% {@code PacketId:16be | RC:8}.
%%
%% UnbindMeta (Opcode 16#0012, BEAM -> Rust):
%% {@code IdLen:16be | ClientId}.

-type subscribe_meta() :: #{packet_id := 1..65535,
                            client_id := binary(),
                            subscriptions := [{binary(), 0..2}]}.
-type suback_meta() :: #{packet_id := 1..65535,
                         codes := [0..2 | 16#80]}.
-type publish_meta() :: #{topic := binary(),
                          packet_id := 0..65535,
                          qos := 0..2,
                          retain := boolean(),
                          dup := boolean()}.
-type puback_meta() :: #{packet_id := 1..65535,
                         return_code := 0..255}.

%% @doc Encode SubscribeIn metadata.
-spec encode_subscribe_meta(1..65535, binary(), [{binary(), 0..2}]) -> binary().
encode_subscribe_meta(PacketId, ClientId, Subs)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535,
       is_binary(ClientId), is_list(Subs) ->
    ok = validate_meta_subs(Subs),
    SubBin = lists:foldl(
        fun({Filter, QoS}, Acc) ->
            <<Acc/binary, (byte_size(Filter)):16/big, Filter/binary, QoS:8>>
        end, <<>>, Subs),
    <<PacketId:16/big, (byte_size(ClientId)):16/big, ClientId/binary,
      (length(Subs)):16/big, SubBin/binary>>.

%% @doc Decode SubscribeIn metadata.
-spec decode_subscribe_meta(binary()) -> {ok, subscribe_meta()} | {error, term()}.
decode_subscribe_meta(<<PacketId:16/big, IdLen:16/big, Rest/binary>>)
  when PacketId =/= 0 ->
    case Rest of
        <<ClientId:IdLen/binary, N:16/big, Tail/binary>> ->
            case decode_meta_subs(Tail, N, []) of
                {ok, Subs} ->
                    {ok, #{packet_id => PacketId,
                           client_id => ClientId,
                           subscriptions => Subs}};
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, malformed_subscribe_meta}
    end;
decode_subscribe_meta(_) ->
    {error, malformed_subscribe_meta}.

%% @doc Encode SubAckOut metadata.
-spec encode_suback_meta(1..65535, [0..2 | 16#80]) -> binary().
encode_suback_meta(PacketId, Codes)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535, is_list(Codes) ->
    <<PacketId:16/big, (list_to_binary(Codes))/binary>>.

%% @doc Decode SubAckOut metadata.
-spec decode_suback_meta(binary()) -> {ok, suback_meta()} | {error, term()}.
decode_suback_meta(<<PacketId:16/big, Codes/binary>>) when PacketId =/= 0 ->
    {ok, #{packet_id => PacketId, codes => binary_to_list(Codes)}};
decode_suback_meta(_) ->
    {error, malformed_suback_meta}.

%% @doc Encode PublishMeta (both PublishIn and PublishOut directions).
-spec encode_publish_meta(binary(), 0..65535, 0..2, boolean(), boolean()) -> binary().
encode_publish_meta(Topic, PacketId, QoS, Retain, Dup)
  when is_binary(Topic), byte_size(Topic) >= 1,
       is_integer(PacketId), PacketId >= 0, PacketId =< 65535,
       (QoS =:= 0 orelse QoS =:= 1 orelse QoS =:= 2),
       is_boolean(Retain), is_boolean(Dup) ->
    R = case Retain of true -> 1; false -> 0 end,
    D = case Dup of true -> 1; false -> 0 end,
    <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big, QoS:8, R:8, D:8>>.

%% @doc Decode PublishMeta.
-spec decode_publish_meta(binary()) -> {ok, publish_meta()} | {error, term()}.
decode_publish_meta(<<TopicLen:16/big, Rest/binary>>) when TopicLen > 0 ->
    case Rest of
        <<Topic:TopicLen/binary, PacketId:16/big, QoS:8, R:8, D:8>>
          when (QoS =:= 0 orelse QoS =:= 1 orelse QoS =:= 2),
               (R =:= 0 orelse R =:= 1), (D =:= 0 orelse D =:= 1) ->
            {ok, #{topic => Topic,
                   packet_id => PacketId,
                   qos => QoS,
                   retain => R =:= 1,
                   dup => D =:= 1}};
        _ ->
            {error, malformed_publish_meta}
    end;
decode_publish_meta(_) ->
    {error, malformed_publish_meta}.

%% @doc Encode PubAckOut metadata.
-spec encode_puback_meta(1..65535, 0..255) -> binary().
encode_puback_meta(PacketId, RC)
  when is_integer(PacketId), PacketId >= 1, PacketId =< 65535,
       is_integer(RC), RC >= 0, RC =< 255 ->
    <<PacketId:16/big, RC:8>>.

%% @doc Decode PubAckOut metadata.
-spec decode_puback_meta(binary()) -> {ok, puback_meta()} | {error, term()}.
decode_puback_meta(<<PacketId:16/big, RC:8>>) when PacketId =/= 0 ->
    {ok, #{packet_id => PacketId, return_code => RC}};
decode_puback_meta(_) ->
    {error, malformed_puback_meta}.

%% @doc Encode UnbindConnection metadata (client identity).
-spec encode_unbind_meta(binary()) -> binary().
encode_unbind_meta(ClientId) when is_binary(ClientId) ->
    <<(byte_size(ClientId)):16/big, ClientId/binary>>.

%% @doc Decode UnbindConnection metadata.
-spec decode_unbind_meta(binary()) -> {ok, #{client_id := binary()}} | {error, term()}.
decode_unbind_meta(<<IdLen:16/big, Rest/binary>>) ->
    case Rest of
        <<ClientId:IdLen/binary>> ->
            {ok, #{client_id => ClientId}};
        _ ->
            {error, malformed_unbind_meta}
    end;
decode_unbind_meta(_) ->
    {error, malformed_unbind_meta}.

%% @doc Encode ConnClose metadata (always empty; W0-24 contract).
-spec encode_connclose_meta() -> binary().
encode_connclose_meta() ->
    <<>>.

%% @doc Decode ConnClose metadata (only empty is valid).
-spec decode_connclose_meta(binary()) -> {ok, #{}} | {error, term()}.
decode_connclose_meta(<<>>) ->
    {ok, #{}};
decode_connclose_meta(_) ->
    {error, malformed_connclose_meta}.

validate_meta_subs([]) -> erlang:error(badarg);
validate_meta_subs(Subs) -> validate_meta_subs(Subs, 0).

validate_meta_subs([], N) when N > 0, N =< 65535 -> ok;
validate_meta_subs([], _) -> erlang:error(badarg);
validate_meta_subs([{Filter, QoS} | Rest], N)
  when is_binary(Filter), byte_size(Filter) > 0,
       (QoS =:= 0 orelse QoS =:= 1 orelse QoS =:= 2) ->
    validate_meta_subs(Rest, N + 1);
validate_meta_subs(_, _) -> erlang:error(badarg).

decode_meta_subs(Rest, 0, Acc) ->
    case Rest of
        <<>> -> {ok, lists:reverse(Acc)};
        _ -> {error, malformed_subscribe_meta}
    end;
decode_meta_subs(<<FilterLen:16/big, Rest/binary>>, N, Acc) when FilterLen > 0, N > 0 ->
    case Rest of
        <<Filter:FilterLen/binary, QoS:8, Tail/binary>>
          when QoS =:= 0 orelse QoS =:= 1 orelse QoS =:= 2 ->
            decode_meta_subs(Tail, N - 1, [{Filter, QoS} | Acc]);
        _ ->
            {error, malformed_subscribe_meta}
    end;
decode_meta_subs(_, _, _) ->
    {error, malformed_subscribe_meta}.

%%====================================================================
%% gen_server IPC client API
%%====================================================================

%% @doc Start an unregistered BrokerLink IPC client with default options.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

%% @doc Start a BrokerLink IPC client.
%%
%% Options:
%% <ul>
%% <li>{@code {transport, tcp | uds}} — default {@code tcp}.</li>
%% <li>{@code {host, Host}} — TCP host, default {@code "127.0.0.1"}.</li>
%% <li>{@code {port, Port}} — TCP port, default {@code 18883}.</li>
%% <li>{@code {path, Path}} — UDS socket path (required for {@code uds}).</li>
%% <li>{@code {reconnect, boolean()}} — when true, a dropped IPC socket
%% is re-established with exponential backoff instead of stopping the
%% server (Sprint 11 restart immunity). Default {@code false}: initial
%% connect failures still fail startup fast.</li>
%% <li>{@code {backoff_base_ms, Ms}} — first reconnect delay, default 100.</li>
%% <li>{@code {backoff_max_ms, Ms}} — reconnect delay cap, default 5000.</li>
%% </ul>
-spec start_link([start_opt()]) -> {ok, pid()} | {error, term()}.
start_link(Opts) when is_list(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

%% @doc Stop the IPC client.
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% @doc Send a Ping for ConnId. Sequence numbers auto-increment.
-spec ping(pid(), non_neg_integer()) -> ok | {error, term()}.
ping(Pid, ConnId) when is_pid(Pid), is_integer(ConnId), ConnId >= 0 ->
    gen_server:call(Pid, {ping, ConnId}, 5000).

%% @doc Send a generic frame with an explicit sequence number.
%%
%% PERF-09 bounded ingress: when the shard server's pending-call queue
%% is at or past `?SEND_QUEUE_BOUND', the frame is rejected immediately
%% with `{error, overloaded}' instead of queueing behind the backlog
%% (where it would sit until the 5 s call timeout killed the calling
%% connection). Callers shed QoS 0 on this signal and keep any other
%% failure semantics unchanged. The check-then-call is a soft bound:
%% concurrent callers may overshoot it slightly, which only delays
%% shedding, never correctness.
-spec send(pid(), opcode(), non_neg_integer(), non_neg_integer(),
           binary(), binary()) -> ok | {error, term()}.
send(Pid, Opcode, ConnId, SeqNo, MetaBin, PayloadBin) ->
    case ingress_overloaded(Pid) of
        true ->
            {error, overloaded};
        false ->
            gen_server:call(Pid, {send, Opcode, ConnId, SeqNo, MetaBin, PayloadBin}, 5000)
    end.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Opts) ->
    Transport = proplists:get_value(transport, Opts, tcp),
    Host = proplists:get_value(host, Opts, ?DEFAULT_HOST),
    Port = proplists:get_value(port, Opts, ?DEFAULT_PORT),
    Path = proplists:get_value(path, Opts, undefined),
    Reconnect = proplists:get_value(reconnect, Opts, false),
    BaseMs = proplists:get_value(backoff_base_ms, Opts, 100),
    MaxMs = proplists:get_value(backoff_max_ms, Opts, 5000),
    case connect(Transport, Host, Port, Path) of
        {ok, Sock} ->
            State = #{sock => Sock,
                      transport => Transport,
                      host => Host,
                      port => Port,
                      path => Path,
                      buffer => <<>>,
                      seq => 0,
                      reconnect => Reconnect,
                      backoff_base_ms => BaseMs,
                      backoff_max_ms => MaxMs,
                      attempt => 0,
                      timer => undefined},
            notify_up(),
            {ok, State};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call({ping, ConnId}, From, State) ->
    Seq = maps:get(seq, State) + 1,
    Frame = encode_frame(ping, ConnId, Seq, <<>>, <<>>),
    send_coalesced(State, From, Frame, Seq);
handle_call({send, Opcode, ConnId, SeqNo, MetaBin, PayloadBin}, From, State) ->
    try encode_frame(Opcode, ConnId, SeqNo, MetaBin, PayloadBin) of
        Frame ->
            send_coalesced(State, From, Frame, maps:get(seq, State))
    catch
        error:badarg -> {reply, {error, frame_too_large}, State}
    end;
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({tcp, Sock, Data}, #{sock := Sock} = State) ->
    Buf = <<(maps:get(buffer, State))/binary, Data/binary>>,
    NewState = drain_buffer(State#{buffer => Buf}),
    {noreply, NewState};
handle_info({tcp_closed, Sock}, #{sock := Sock} = State) ->
    handle_ipc_down(tcp_closed, State);
handle_info({tcp_error, Sock, Reason}, #{sock := Sock} = State) ->
    handle_ipc_down({tcp_error, Reason}, State);
handle_info({timeout, Ref, reconnect}, #{timer := Ref} = State) ->
    attempt_reconnect(State#{timer => undefined});
handle_info({timeout, _StaleRef, reconnect}, State) ->
    %% Superseded timer (e.g. after a successful connect reset it).
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_timer(maps:get(timer, State, undefined)),
    case maps:get(sock, State, undefined) of
        Sock when is_port(Sock) -> catch gen_tcp:close(Sock);
        _ -> ok
    end,
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal helpers
%%====================================================================

%% @doc Socket options for the BrokerLink TCP connection.
%% `nodelay' avoids delayed-ACK interaction on small frames;
%% 64 KiB buffers bound per-connection memory while giving the
%% edge-kernel burst path headroom.
-spec brokerlink_sock_opts() -> [term()].
brokerlink_sock_opts() ->
    [binary, {packet, raw}, {active, true},
     {nodelay, true}, {recbuf, 65536}, {sndbuf, 65536}].

connect(tcp, Host, Port, _Path) ->
    gen_tcp:connect(Host, Port, brokerlink_sock_opts());
connect(uds, _Host, _Port, undefined) ->
    {error, {missing_option, path}};
connect(uds, _Host, _Port, Path) ->
    gen_tcp:connect({local, Path}, 0, [binary, {packet, raw}, {active, true}]).

transport_send(#{sock := Sock}, Frame) when is_port(Sock) ->
    gen_tcp:send(Sock, Frame);
transport_send(_State, _Frame) ->
    {error, not_connected}.

%% PERF-09: max queued inbound calls a shard sheds past. Normal depth
%% stays far below (single digits per shard at 5k paired load); the
%% pre-shard 5k run peaked at 100 pending on the single client, so 256
%% only trips under genuine overload, never on a healthy stack.
-define(SEND_QUEUE_BOUND, 256).

%% @private True when the shard server already holds at least
%% `?SEND_QUEUE_BOUND' pending calls. Total on dead pids (returns
%% false) so down shards keep their existing failure path.
ingress_overloaded(Pid) when is_pid(Pid) ->
    case catch process_info(Pid, message_queue_len) of
        {message_queue_len, N} -> N >= ?SEND_QUEUE_BOUND;
        _ -> false
    end;
ingress_overloaded(_) ->
    false.

%% PERF-05: flush once per poll on the sender. Coalesce the current
%% frame with already-queued outbound requests (non-blocking drain,
%% bounded by frames and bytes) into a single `gen_tcp:send` iolist.
%% Order is arrival order; no delayed flush. Each drained caller gets
%% its own reply.
-define(SEND_BATCH_MAX_FRAMES, 64).
-define(SEND_BATCH_MAX_BYTES, 65536).

send_coalesced(State, From, Frame, Seq) ->
    {Frames, Froms, Seq1} =
        drain_send_queue([Frame], [From], byte_size(Frame), Seq),
    Result = case Frames of
        [Single] -> transport_send(State, Single);
        Many -> transport_send_batch(State, Many)
    end,
    case Result of
        ok ->
            lists:foreach(fun(F) -> gen_server:reply(F, ok) end, Froms),
            {noreply, State#{seq => Seq1}};
        {error, Reason} ->
            lists:foreach(fun(F) -> gen_server:reply(F, {error, Reason}) end, Froms),
            {noreply, State#{seq => Seq1}}
    end.

drain_send_queue(Frames, Froms, Bytes, Seq) ->
    case length(Frames) >= ?SEND_BATCH_MAX_FRAMES orelse
         Bytes >= ?SEND_BATCH_MAX_BYTES of
        true ->
            {Frames, Froms, Seq};
        false ->
            receive
                {'$gen_call', From2, {ping, ConnId2}} ->
                    Seq2 = Seq + 1,
                    F2 = encode_frame(ping, ConnId2, Seq2, <<>>, <<>>),
                    drain_send_queue(Frames ++ [F2], Froms ++ [From2],
                                     Bytes + byte_size(F2), Seq2);
                {'$gen_call', From2, {send, Op2, C2, S2, M2, P2}} ->
                    try encode_frame(Op2, C2, S2, M2, P2) of
                        F2 ->
                            drain_send_queue(Frames ++ [F2], Froms ++ [From2],
                                             Bytes + byte_size(F2), Seq)
                    catch
                        error:badarg ->
                            gen_server:reply(From2, {error, frame_too_large}),
                            drain_send_queue(Frames, Froms, Bytes, Seq)
                    end
            after 0 ->
                {Frames, Froms, Seq}
            end
    end.

transport_send_batch(#{sock := Sock}, Frames) when is_port(Sock), is_list(Frames) ->
    gen_tcp:send(Sock, Frames);
transport_send_batch(_State, _Frames) ->
    {error, not_connected}.

%% @private The IPC socket died: with `{reconnect, true}` stay alive,
%% tell every connection to hold, and start backing off; otherwise stop
%% as before (Sprint 1 semantics for supervised restarts).
handle_ipc_down(Reason, State) ->
    Sock = maps:get(sock, State, undefined),
    catch gen_tcp:close(Sock),
    State1 = State#{sock => undefined, buffer => <<>>},
    case maps:get(reconnect, State1, false) of
        true ->
            notify_down(),
            schedule_reconnect(State1#{attempt => 0});
        false ->
            {stop, {ipc_closed, Reason}, State1}
    end.

%% @private Schedule one reconnect attempt with backoff + jitter.
%%
%% Uses `erlang:start_timer/3` (not `send_after/3`) precisely because it
%% delivers `{timeout, TimerRef, Msg}` carrying its own return value,
%% which is what the staleness match in `handle_info` compares against.
schedule_reconnect(#{attempt := Attempt} = State) ->
    Base = maps:get(backoff_base_ms, State, 100),
    Max = maps:get(backoff_max_ms, State, 5000),
    Cap = min(Base bsl min(Attempt, 16), Max),
    %% Half fixed, half jittered: spreads simultaneous reconnects.
    Delay = Cap div 2 + rand:uniform(max(Cap div 2, 1)),
    Timer = erlang:start_timer(Delay, self(), reconnect),
    {noreply, State#{timer => Timer}}.

%% @private One reconnect attempt: success sweeps connections back to
%% the core, failure backs off further.
attempt_reconnect(State) ->
    #{transport := Transport, host := Host, port := Port, path := Path} = State,
    case connect(Transport, Host, Port, Path) of
        {ok, Sock} ->
            notify_up(),
            {noreply, State#{sock => Sock, buffer => <<>>, attempt => 0}};
        {error, _Reason} ->
            Attempt = maps:get(attempt, State, 0),
            schedule_reconnect(State#{attempt => Attempt + 1})
    end.

cancel_timer(undefined) -> ok;
cancel_timer(Timer) ->
    catch erlang:cancel_timer(Timer),
    ok.

%% @private Broadcast core presence to every registered connection.
%% Total when the registry is absent. The down broadcast carries our
%% pid so sharded connections hold only for their pinned shard
%% (see indra_conn broker_down handling); the legacy pid-less
%% `{broker_down}' is still honoured by connections as a global hold.
notify_up() ->
    catch indra_conn_registry:notify_all({broker_up, self()}),
    ok.

notify_down() ->
    catch indra_conn_registry:notify_all({broker_down, self()}),
    ok.

%% @private Drain complete frames from the reassembly buffer.
%%
%% No per-frame state is retained: each header is dispatched and then
%% dropped, so shard memory stays flat no matter how many frames flow
%% through. (An earlier version prepended every header to a `frames'
%% list that nothing ever read, leaking ~140 bytes per inbound frame
%% for the life of the edge.)
drain_buffer(State) ->
    Buf = maps:get(buffer, State),
    case decode_frame(Buf) of
        {ok, Header, Meta, Payload, Rest} ->
            dispatch_frame(Header, Meta, Payload),
            drain_buffer(State#{buffer => Rest});
        {more, _Need} ->
            State;
        {error, _Reason} ->
            %% Drop corrupt bytes to avoid a wedged stream; keep running.
            State#{buffer => <<>>}
    end.

%% Opcodes routed to the owning connection process.
-define(DISPATCH_OPCODES, [16#0011, 16#0021, 16#0023, 16#0031, 16#0041]).

%% @private Route an inbound Rust frame to its connection process.
%%
%% Looks the frame ConnId up in {@code indra_conn_registry} and casts the
%% frame to the owner. Total: unknown conns (or a missing registry) are
%% silently dropped so one stray frame can never wedge the IPC client.
dispatch_frame(Header, Meta, Payload) ->
    Opcode = maps:get(opcode, Header),
    case lists:member(Opcode, ?DISPATCH_OPCODES) of
        false ->
            ok;
        true ->
            ConnId = maps:get(conn_id, Header),
            case catch indra_conn_registry:lookup(ConnId) of
                {ok, Pid} ->
                    catch gen_statem:cast(Pid, {broker_frame, Header, Meta, Payload}),
                    ok;
                _ ->
                    ok
            end
    end.
