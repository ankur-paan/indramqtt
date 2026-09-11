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
         decode_bind_meta/1,
         encode_session_binding_meta/3,
         decode_session_binding_meta/1]).

%% gen_server lifecycle + IPC API.
-export([start_link/0,
         start_link/1,
         stop/1,
         ping/2,
         send/6]).

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
                | disconnect_in
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
                   | {path, string()}.

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
%%   +------------------+----------------+-------+------------+
%%   | ClientIdLen:16be | ClientId bytes | Flags | Keepalive  |
%%   |                  |  (UTF-8)       |  :8   |  :16be     |
%%   +------------------+----------------+-------+------------+
%% </pre>
%% Flags bit 0 = clean_start. All other bits are reserved and must be 0.
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
                       keepalive := 0..65535}.
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

%% @doc Decode BindConnection metadata.
-spec decode_bind_meta(binary()) -> {ok, bind_meta()} | {error, term()}.
decode_bind_meta(<<IdLen:16/big, Rest/binary>>) ->
    case Rest of
        <<ClientId:IdLen/binary, Flags:8, Keepalive:16/big>> ->
            {ok, #{client_id => ClientId,
                   clean_start => (Flags band 16#01) =:= 16#01,
                   keepalive => Keepalive}};
        _ ->
            {error, malformed_bind_meta}
    end;
decode_bind_meta(_) ->
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
-spec send(pid(), opcode(), non_neg_integer(), non_neg_integer(),
           binary(), binary()) -> ok | {error, term()}.
send(Pid, Opcode, ConnId, SeqNo, MetaBin, PayloadBin) ->
    gen_server:call(Pid, {send, Opcode, ConnId, SeqNo, MetaBin, PayloadBin}, 5000).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Opts) ->
    Transport = proplists:get_value(transport, Opts, tcp),
    Host = proplists:get_value(host, Opts, ?DEFAULT_HOST),
    Port = proplists:get_value(port, Opts, ?DEFAULT_PORT),
    Path = proplists:get_value(path, Opts, undefined),
    case connect(Transport, Host, Port, Path) of
        {ok, Sock} ->
            State = #{sock => Sock,
                      transport => Transport,
                      host => Host,
                      port => Port,
                      path => Path,
                      buffer => <<>>,
                      seq => 0,
                      last_pong => undefined,
                      frames => []},
            {ok, State};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call({ping, ConnId}, _From, State) ->
    Seq = maps:get(seq, State) + 1,
    Frame = encode_frame(ping, ConnId, Seq, <<>>, <<>>),
    case transport_send(State, Frame) of
        ok ->
            {reply, ok, State#{seq => Seq}};
        {error, Reason} ->
            {reply, {error, Reason}, State#{seq => Seq}}
    end;
handle_call({send, Opcode, ConnId, SeqNo, MetaBin, PayloadBin}, _From, State) ->
    try encode_frame(Opcode, ConnId, SeqNo, MetaBin, PayloadBin) of
        Frame ->
            case transport_send(State, Frame) of
                ok -> {reply, ok, State};
                {error, Reason} -> {reply, {error, Reason}, State}
            end
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
    {stop, {ipc_closed, tcp_closed}, State#{sock => undefined}};
handle_info({tcp_error, Sock, Reason}, #{sock := Sock} = State) ->
    {stop, {ipc_error, Reason}, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{sock := Sock}) when is_port(Sock) ->
    catch gen_tcp:close(Sock),
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal helpers
%%====================================================================

connect(tcp, Host, Port, _Path) ->
    gen_tcp:connect(Host, Port, [binary, {packet, raw}, {active, true}]);
connect(uds, _Host, _Port, undefined) ->
    {error, {missing_option, path}};
connect(uds, _Host, _Port, Path) ->
    gen_tcp:connect({local, Path}, 0, [binary, {packet, raw}, {active, true}]).

transport_send(#{sock := Sock}, Frame) when is_port(Sock) ->
    gen_tcp:send(Sock, Frame);
transport_send(_State, _Frame) ->
    {error, not_connected}.

%% @private Drain complete frames from the reassembly buffer.
drain_buffer(State) ->
    Buf = maps:get(buffer, State),
    case decode_frame(Buf) of
        {ok, Header, _Meta, _Payload, Rest} ->
            Frames = [Header | maps:get(frames, State)],
            State1 = case maps:get(opcode, Header) of
                16#0002 ->
                    State#{last_pong => Header, frames => Frames, buffer => Rest};
                _ ->
                    State#{frames => Frames, buffer => Rest}
            end,
            drain_buffer(State1);
        {more, _Need} ->
            State;
        {error, _Reason} ->
            %% Drop corrupt bytes to avoid a wedged stream; keep running.
            State#{buffer => <<>>}
    end.
