%% @doc One MQTT client connection (BEAM edge side).
%%
%% Connection != Session: this process owns a single client TCP socket
%% (framing, keepalive supervision) and borrows session truth from the
%% Rust core over BrokerLink. It never stores subscriptions or retained
%% messages itself.
%%
%% State machine: {@code await_connect -> connected <-> await_core}.
%% <ul>
%% <li>{@code await_connect}: buffers TCP bytes until a full CONNECT
%% decodes, forwards a {@code BindConnection} frame to the broker, and
%% waits for the {@code SessionBinding} reply.</li>
%% <li>{@code connected}: runs the messaging loop — SUBSCRIBE forwards to
%% Rust and answers SUBACK, PUBLISH forwards raw bytes (QoS 1 answered
%% with PUBACK), PINGREQ is answered on the edge, DISCONNECT unbinds
%% (suppressing the CONNECT will) and closes while any other death
%% reports to the kernel so a stored will fires once. Inbound Rust
%% frames (PublishOut, PubAckOut, SubAckOut) are
%% encoded back onto the socket. MQTT keepalive (1.5 x keepalive seconds)
%% still supervises idle peers.</li>
%% <li>{@code await_core}: the BrokerLink IPC is down (core crash,
%% restart, rolling upgrade). The client socket stays OPEN: inbound bytes
%% buffer (bounded), PINGREQ is still answered so the peer keepalive
%% survives, everything else waits. On core return the session re-binds
%% (always non-clean, to resume-or-recreate) and, when the core lost
%% state, every tracked subscription re-registers silently.</li>
%% </ul>
%%
%% Inbound Rust frames normally arrive via {@code indra_brokerlink},
%% which routes them through {@code indra_conn_registry}; {@link
%% broker_frame/4} is the same entry point for tests and direct callers.
%% Core presence arrives as {@code {broker_up, Pid}} /
%% {@code {broker_down, Pid}} casts (broadcast by the brokerlink client).
%% The down broadcast carries the shard pid so only connections pinned
%% to that shard hold; other shards ignore it. The legacy pid-less
%% {@code {broker_down}} is still honoured as a global hold (single
%% shard, older callers).
%%
%% Broker protocol (also implemented by test mocks): the broker is any
%% process answering {@code gen_server:call(Broker, {send, Opcode,
%% ConnId, SeqNo, Meta, Payload}, Timeout)}. Inbound Rust frames arrive
%% via {@link broker_frame/4}.
-module(indra_conn).

-behaviour(gen_statem).

-export([start_link/2,
         stop/1,
         broker_frame/4,
         pick_shard/2,
         shard_index/2,
         conn_sock_opts/0,
         drain_close_discards/0]).

%% gen_statem callbacks.
-export([callback_mode/0,
         init/1,
         handle_event/4,
         terminate/3]).

-define(BIND_CONNECTION, 16#0010).
-define(SESSION_BINDING, 16#0011).
-define(UNBIND_CONNECTION, 16#0012).
-define(PUBLISH_IN, 16#0020).
-define(PUBLISH_OUT, 16#0021).
-define(PUBACK_IN, 16#0022).
-define(PUBACK_OUT, 16#0023).
-define(PUBREC_IN, 16#0024).
-define(PUBREC_OUT, 16#0025).
-define(PUBREL_IN, 16#0026).
-define(PUBREL_OUT, 16#0027).
-define(PUBCOMP_IN, 16#0028).
-define(PUBCOMP_OUT, 16#0029).
-define(SUBSCRIBE_IN, 16#0030).
-define(SUBACK_OUT, 16#0031).
-define(CONN_CLOSE, 16#0041).
-define(DISCONNECT_IN, 16#0040).
-define(DEFAULT_CONNECT_TIMEOUT_MS, 10000).
%% Max client bytes buffered while the core is down; beyond this the
%% connection fails closed instead of ballooning the edge.
-define(MAX_HOLD_BUFFER_BYTES, 1048576).

-type conn_opt() :: {broker, pid() | [pid()]}
                   | {conn_id, non_neg_integer()}
                   | {connect_timeout_ms, pos_integer()}
                   | {psk_identity, binary()}
                   | {ws_max_frame_bytes, pos_integer()}
                   | {transport, tcp | ssl | ws | wss}.

%%=============================================================%% API
%%=============================================================
%% @doc Start a connection process for an accepted socket.
%%
%% The socket must be in passive mode and owned by the caller; ownership
%% is transferred here on {@code takeover}. Options:
%% <ul>
%% <li>{@code {broker, pid() | [pid()]}} — required BrokerLink shard
%% client (or mock). A list pins the connection to exactly one shard by
%% {@code conn_id rem K}; see {@link pick_shard/2}.</li>
%% <li>{@code {conn_id, N}} — BrokerLink connection id; defaults to a
%% fresh positive unique integer.</li>
%% <li>{@code {connect_timeout_ms, Ms}} — first-packet deadline,
%% default 10000.</li>
%% <li>{@code {psk_identity, Id}} — TLS PSK identity the listener
%% negotiated for this socket (B5-05). The conn maps it onto the bind
%% username so the kernel authenticates and authorizes it like any
%% other CONNECT identity; a CONNECT username that is neither absent
%% nor identical fails the connection closed with no bind sent. Absent
%% on plaintext and certificate connections (unchanged path).</li>
%% <li>{@code {transport, tcp | ssl | ws | wss}} — socket driver; default
%% {@code tcp}. Must match how the socket was accepted: {@code ws} is a
%% plaintext socket that already completed the WebSocket upgrade, and
%% {@code wss} is a TLS socket that completed its TLS handshake first
%% and then the WebSocket upgrade (see {@link indra_ws_listener}), so
%% MQTT bytes travel inside WS binary messages on the same bind path as
%% TCP.</li>
%% <li>{@code {ws_max_frame_bytes, N}} — WS frame and reassembled-message
%% cap for {@code ws}/{@code wss} transports, default 1 MiB (see
%% {@link indra_ws:default_max_frame_bytes/0}). Ignored otherwise.</li>
%% </ul>
-spec start_link(gen_tcp:socket(), [conn_opt()]) -> {ok, pid()} | {error, term()}.
start_link(Sock, Opts) when is_list(Opts) ->
    gen_statem:start_link(?MODULE, {Sock, Opts}, []).

%% @doc Stop the connection process (closes the socket).
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_statem:stop(Pid).

%% @doc Deliver one inbound BrokerLink frame from the Rust core.
-spec broker_frame(pid(), map(), binary(), binary()) -> ok.
broker_frame(Pid, Header, Meta, Payload) ->
    gen_statem:cast(Pid, {broker_frame, Header, Meta, Payload}).

%%=============================================================%% gen_statem callbacks
%%=============================================================
callback_mode() ->
    handle_event_function.

%% @doc Pin a connection id to one shard pid. The pin is
%% `conn_id rem K' (0-based index into the shard list) and never
%% changes for the life of the connection. No session, routing, auth
%% or retry logic lives here: this is routing only.
-spec pick_shard(non_neg_integer(), [pid()]) -> pid().
pick_shard(ConnId, Shards)
  when is_integer(ConnId), ConnId >= 0, is_list(Shards) ->
    lists:nth(shard_index(ConnId, length(Shards)) + 1, Shards).

%% @doc 0-based shard index for a connection id and shard count K.
-spec shard_index(non_neg_integer(), pos_integer()) -> non_neg_integer().
shard_index(ConnId, K)
  when is_integer(ConnId), ConnId >= 0, is_integer(K), K >= 1 ->
    ConnId rem K.

init({Sock, Opts}) ->
    case proplists:get_value(broker, Opts) of
        undefined ->
            {stop, {missing_option, broker}};
        [] ->
            {stop, {missing_option, broker}};
        Broker when is_pid(Broker) ->
            init_shard(Sock, Opts, [Broker]);
        Brokers when is_list(Brokers) ->
            case lists:all(fun is_pid/1, Brokers) andalso Brokers =/= [] of
                true ->
                    init_shard(Sock, Opts, Brokers);
                false ->
                    {stop, {missing_option, broker}}
            end;
        _ ->
            {stop, {missing_option, broker}}
    end.

%% @private Shared init once the shard list is normalised. The pin is
%% fixed here and `broker' always holds the pinned pid.
init_shard(Sock, Opts, Shards) ->
    ConnId = proplists:get_value(conn_id, Opts,
                                 erlang:unique_integer([positive, monotonic])),
    Timeout = proplists:get_value(connect_timeout_ms, Opts,
                                   ?DEFAULT_CONNECT_TIMEOUT_MS),
    Transport = proplists:get_value(transport, Opts, tcp),
    PskIdentity = proplists:get_value(psk_identity, Opts, undefined),
    case PskIdentity of
        undefined ->
            init_shard_validated(Sock, Opts, Shards, ConnId, Timeout, Transport, undefined);
        PskIdentity when is_binary(PskIdentity) ->
            init_shard_validated(Sock, Opts, Shards, ConnId, Timeout, Transport, PskIdentity);
        _ ->
            {stop, {invalid_option, psk_identity}}
    end.

%% @private Build the initial connection state. `psk_identity' is the
%% TLS PSK identity the listener negotiated (`undefined' on plaintext
%% and certificate sockets); it is consulted at CONNECT time to map
%% the bind username (see handle_connect_packet/3).
init_shard_validated(Sock, Opts, Shards, ConnId, Timeout, Transport, PskIdentity) ->
    SockMod = case Transport of ssl -> ssl; ws -> ws; wss -> wss; _ -> gen_tcp end,
    WsMax = proplists:get_value(ws_max_frame_bytes, Opts,
                                indra_ws:default_max_frame_bytes()),
    Broker = pick_shard(ConnId, Shards),
    Data = #{sock => Sock,
             sockmod => SockMod,
             broker => Broker,
             brokers => Shards,
             shard => shard_index(ConnId, length(Shards)),
             conn_id => ConnId,
             connect_timeout_ms => Timeout,
             buffer => <<>>,
             seq => 0,
             %% B5-05 TLS PSK identity negotiated for this socket
             %% (`undefined' on plaintext and certificate sockets).
             %% Mapped onto the bind username at CONNECT time; the
             %% kernel then authenticates and authorizes it like any
             %% other CONNECT identity.
             psk_identity => PskIdentity,
             pending => undefined,
             client_id => undefined,
             keepalive => 0,
             %% F1-01 last will captured from CONNECT (undefined when
             %% the client registered none). Forwarded in every bind
             %% (including rebinds after a core restart) and reported
             %% via DisconnectIn on ungraceful close; the kernel owns
             %% the session and the publish decision.
             will => undefined,
             %% B4-05 negotiated protocol level (4 or 5) and the
             %% CONNECT Topic Alias Maximum (client receive limit).
             %% Level gates the CONNACK shape and PUBLISH decoding;
             %% the maximum rides every (re)bind so the kernel
             %% outbound table survives core restarts.
             proto_level => 4,
             client_alias_max => 0,
             %% WS reassembly state (used only when `sockmod' is `ws'
             %% or `wss'): `ws_buf' holds the raw unparsed frame tail,
             %% `ws_frag' the open fragmented message, `ws_max_frame'
             %% its bound.
             ws_buf => <<>>,
             ws_frag => none,
             ws_max_frame => WsMax,
             session_id => undefined,
             subs_pending => #{},
             pubs_pending => #{},
             qos2_pending => #{},
             subs => #{},
             quiet_subs => #{},
             rebinding => false,
             %% PERF-09: QoS 0 publishes shed while the owning
             %% shard is past its ingress bound. Observable via
             %% sys:get_state (the existing OTP status path); no
             %% other surface was added.
             qos0_dropped => 0,
             %% PERF-10: outbound frames dropped after a client-socket
             %% send failure. Observable via sys:get_state (the
             %% existing OTP status path); no other surface was added.
             send_failed_dropped => 0,
             %% Egress stage 0: the stop cause recorded for the
             %% stop-cause aggregates (read back in terminate/3; state
             %% dies with the process, counters do not). Every stop
             %% site sets it through stop_with/2; `unknown' means a
             %% path was missed and is counted, not hidden.
             stop_cause => undefined},
    {ok, await_connect, Data}.

%% @private True when Pid is a known shard other than our pinned one.
%% Announcements from other shards are ignored: each connection only
%% follows its own shard.
is_other_shard(Pid, #{broker := Pinned, brokers := Shards}) when is_pid(Pid) ->
    Pid =/= Pinned andalso lists:member(Pid, Shards);
is_other_shard(_, _) ->
    false.

%% @private Adopt a replacement broker pid (single-shard restart).
%% The shard list tracks the live pid so later announcements compare
%% against the current identity.
adopt_broker(Data, NewBroker) ->
    case maps:get(brokers, Data, undefined) of
        [_Old] ->
            Data#{broker => NewBroker, brokers => [NewBroker]};
        _ ->
            Data#{broker => NewBroker}
    end.

%% @private Adopt the replacement pid for our pinned shard slot
%% (multi-shard restart). The pin (shard index) never changes: only
%% the pid at that index is replaced, so sibling shards keep their
%% own connections.
replace_shard(#{brokers := Shards, shard := Idx} = Data, NewBroker) ->
    Data#{broker => NewBroker,
          brokers => replace_nth(Idx + 1, Shards, NewBroker)}.

%% @private Replace the Nth (1-based) list element.
replace_nth(1, [_ | _Rest], New) ->
    [New | _Rest];
replace_nth(N, [H | Rest], New) when N > 1 ->
    [H | replace_nth(N - 1, Rest, New)].

%% @private Registered pid for our pinned shard slot, or undefined
%% when the registry has no entry (unit tests, or the gap between a
%% restart announcement and the supervisor registering the
%% replacement). K = 1 keeps the historic `indra_edge_brokerlink'
%% name; K > 1 uses `indra_edge_sup:shard_name/1'.
own_shard_pid(#{brokers := Shards, shard := Idx}) ->
    try
        Name = case length(Shards) of
                   1 -> indra_edge_brokerlink;
                   _ -> indra_edge_sup:shard_name(Idx + 1)
               end,
        whereis(Name)
    catch
        _:_ -> undefined
    end.

%% @private Classify an unknown broker_up pid (neither the pinned pid
%% nor a listed shard) in multi-shard mode:
%% - pinned alive: ignore, our shard is fine and this is another
%%   shard's news;
%% - pinned dead and the registry already names our slot (the
%%   supervisor registers each restarted shard before announcing it):
%%   adopt the registered pid, which is NewBroker on the timely path;
%% - pinned dead but our slot has no registered pid yet (announcement
%%   arrived before registration): defer. The supervisor emits a
%%   post-registration announcement per restarted shard, which drives
%%   the adoption then; adopting blindly here could collapse every
%%   connection onto the first shard to announce.
classify_unknown(Data, NewBroker) ->
    case is_process_alive(maps:get(broker, Data)) of
        true ->
            ignore;
        false ->
            case own_shard_pid(Data) of
                NewBroker ->
                    {adopt, NewBroker};
                Own when is_pid(Own) ->
                    {adopt, Own};
                undefined ->
                    defer
            end
    end.

%% --- takeover: claim a transferred socket and arm it -----------------
handle_event(cast, takeover, await_connect,
             #{sock := Sock, sockmod := Mod, conn_id := ConnId,
               connect_timeout_ms := Timeout} = Data) ->
    ok = indra_conn_registry:register(ConnId, self()),
    case sock_setopts(Mod, Sock) of
        ok ->
            {keep_state, Data, [{state_timeout, Timeout, connect_timeout}]};
        {error, _} ->
            {stop, normal, Data#{stop_cause => tcp_error}}
    end;

%% --- core presence ----------------------------------------------------
%% Await-connect has no session to hold: adopt a new broker pid so the
%% pending handshake (if any) can be re-driven on arrival. With
%% sharding only our pinned shard is followed; announcements from
%% other shards are ignored.
handle_event(cast, {broker_up, NewBroker}, await_connect, Data) ->
    case is_other_shard(NewBroker, Data) of
        true ->
            {keep_state, Data};
        false ->
            case NewBroker =:= maps:get(broker, Data) of
                true ->
                    {keep_state, Data};
                false ->
                    case maps:get(brokers, Data, [maps:get(broker, Data)]) of
                        [_Single] ->
                            Data1 = adopt_broker(Data, NewBroker),
                            case maps:get(pending, Data1, undefined) of
                                undefined ->
                                    {keep_state, Data1};
                                _ ->
                                    resend_bind(Data1)
                            end;
                        _ ->
                            %% Multi-shard restart: adopt the replacement
                            %% for our pinned slot, if identifiable (see
                            %% classify_unknown/2); otherwise ignore so
                            %% connections never collapse onto one shard.
                            case classify_unknown(Data, NewBroker) of
                                {adopt, Own} ->
                                    Data1 = replace_shard(Data, Own),
                                    case maps:get(pending, Data1, undefined) of
                                        undefined ->
                                            {keep_state, Data1};
                                        _ ->
                                            resend_bind(Data1)
                                    end;
                                _ ->
                                    {keep_state, Data}
                            end
                    end
            end
    end;
handle_event(cast, {broker_down}, await_connect, Data) ->
    {keep_state, Data};
%% Scoped down: only our pinned shard parks the handshake; other
%% shards' news is ignored so no hold storm spreads.
handle_event(cast, {broker_down, Pid}, await_connect, Data) when is_pid(Pid) ->
    case Pid =:= maps:get(broker, Data) of
        true ->
            {keep_state, Data};
        false ->
            {keep_state, Data}
    end;
%% Connected with a fresh broker identity (restart): hold and rebind.
handle_event(cast, {broker_up, NewBroker}, connected, Data) ->
    case is_other_shard(NewBroker, Data) of
        true ->
            {keep_state, Data};
        false ->
            case NewBroker =:= maps:get(broker, Data) of
                true ->
                    {keep_state, Data};
                false ->
                    case maps:get(brokers, Data, [maps:get(broker, Data)]) of
                        [_Single] ->
                            start_rebind(adopt_broker(Data, NewBroker));
                        _ ->
                            %% Multi-shard restart: rebind via the
                            %% replacement for our pinned slot, if
                            %% identifiable; otherwise hold the pin.
                            case classify_unknown(Data, NewBroker) of
                                {adopt, Own} ->
                                    start_rebind(replace_shard(Data, Own));
                                _ ->
                                    {keep_state, Data}
                            end
                    end
            end
    end;
handle_event(cast, {broker_down}, connected, Data) ->
    {next_state, await_core, Data};
%% Scoped down: hold only when our pinned shard reports; news from
%% another shard (or an unknown pid) is ignored so surviving shards
%% see no hold/rebind storm.
handle_event(cast, {broker_down, Pid}, connected, Data) when is_pid(Pid) ->
    case Pid =:= maps:get(broker, Data) of
        true ->
            {next_state, await_core, Data};
        false ->
            {keep_state, Data}
    end;
%% Already holding: adopt + rebind unless a rebind is already in flight.
%% Announcements from other shards are ignored so connections never
%% collapse onto one shard; an unknown pid in a multi-shard setup is
%% adopted only when it (or the registry) identifies the replacement
%% for our pinned slot (see classify_unknown/2).
handle_event(cast, {broker_up, NewBroker}, await_core, Data) ->
    case is_other_shard(NewBroker, Data) of
        true ->
            {keep_state, Data};
        false ->
            Pinned = maps:get(broker, Data),
            Shards = maps:get(brokers, Data, [Pinned]),
            case NewBroker =:= Pinned of
                true ->
                    case maps:get(rebinding, Data, false) of
                        true ->
                            {keep_state, Data};
                        false ->
                            start_rebind(Data)
                    end;
                false ->
                    case length(Shards) of
                        1 ->
                            Data1 = adopt_broker(Data, NewBroker),
                            case maps:get(rebinding, Data1, false) of
                                true ->
                                    {keep_state, Data1};
                                false ->
                                    start_rebind(Data1)
                            end;
                        _ ->
                            case classify_unknown(Data, NewBroker) of
                                {adopt, Own} ->
                                    Data1 = replace_shard(Data, Own),
                                    case maps:get(rebinding, Data1, false) of
                                        true ->
                                            {keep_state, Data1};
                                        false ->
                                            start_rebind(Data1)
                                    end;
                                _ ->
                                    {keep_state, Data}
                            end
                    end
            end
    end;
handle_event(cast, {broker_down}, await_core, Data) ->
    {keep_state, Data};
%% Scoped down while already holding: nothing further to do either
%% way; the clause exists so other shards' news never disturbs the
%% pin (it stays on the owning shard until its replacement announces).
handle_event(cast, {broker_down, Pid}, await_core, Data) when is_pid(Pid) ->
    {keep_state, Data};

%% --- inbound BrokerLink frames ---------------------------------------
handle_event(cast, {broker_frame, Header, Meta, _Payload}, await_connect, Data) ->
    case maps:get(opcode, Header, undefined) of
        ?SESSION_BINDING ->
            handle_session_binding(Meta, Data);
        _ ->
            %% Not for this handshake (e.g. stray Pong): ignore, keep waiting.
            {keep_state, Data}
    end;
handle_event(cast, {broker_frame, Header, Meta, Payload}, connected, Data) ->
    case maps:get(opcode, Header, undefined) of
        ?SUBACK_OUT ->
            handle_suback(Meta, Data);
        ?PUBLISH_OUT ->
            egress_batch({Header, Meta, Payload}, Data);
        ?PUBACK_OUT ->
            handle_puback_out(Meta, Data);
        ?PUBREC_OUT ->
            egress_batch({Header, Meta, Payload}, Data);
        ?PUBREL_OUT ->
            egress_batch({Header, Meta, Payload}, Data);
        ?PUBCOMP_OUT ->
            egress_batch({Header, Meta, Payload}, Data);
        ?CONN_CLOSE ->
            %% Kernel-ordered close (W0-25): the kernel already unbound
            %% session state; the edge only closes the socket. terminate/3
            %% closes the socket and unregisters the conn id.
            stop_with(Data, kernel_close);
        _ ->
            %% Late duplicates or future opcodes: ignore for now.
            {keep_state, Data}
    end;
handle_event(cast, {broker_frame, Header, Meta, _Payload}, await_core, Data) ->
    case maps:get(opcode, Header, undefined) of
        ?SESSION_BINDING ->
            handle_rebind_binding(Meta, Data);
        ?CONN_CLOSE ->
            %% Socket is managed by the hold/buffering logic: drop.
            {keep_state, Data};
        _ ->
            %% Stale pre-crash frames: ignore while holding.
            {keep_state, Data}
    end;

%% --- client WSS bytes: unwrap binary messages to MQTT first --------
%% A `wss' socket delivers `{ssl, Sock, Bytes}' (TLS-decrypted WS
%% frames). These clauses must precede the generic `{ssl, ...}'
%% normalization below, which is only for plain `ssl' sockets; routing
%% WSS bytes through it would treat WS framing as raw MQTT. Decoding
%% and the bind path are otherwise identical to `ws'.
handle_event(info, {ssl, Sock, Bytes}, await_connect,
             #{sock := Sock, sockmod := wss} = Data) ->
    case ws_mqtt_bytes(Bytes, Data) of
        {mqtt, <<>>, Data1} ->
            {keep_state, Data1};
        {mqtt, Mqtt, Data1} ->
            Buf = <<(maps:get(buffer, Data1))/binary, Mqtt/binary>>,
            handle_connect_bytes(Buf, Data1#{buffer => <<>>});
        {stop, _, _} = Stop ->
            Stop
    end;
handle_event(info, {ssl, Sock, Bytes}, connected,
             #{sock := Sock, sockmod := wss} = Data) ->
    case ws_mqtt_bytes(Bytes, Data) of
        {mqtt, <<>>, Data1} ->
            {keep_state, Data1};
        {mqtt, Mqtt, Data1} ->
            Buf = <<(maps:get(buffer, Data1))/binary, Mqtt/binary>>,
            handle_connected_bytes(Buf, Data1#{buffer => <<>>});
        {stop, _, _} = Stop ->
            Stop
    end;
handle_event(info, {ssl, Sock, Bytes}, await_core,
             #{sock := Sock, sockmod := wss} = Data) ->
    case ws_mqtt_bytes(Bytes, Data) of
        {mqtt, <<>>, Data1} ->
            {keep_state, Data1};
        {mqtt, Mqtt, Data1} ->
            Buf = <<(maps:get(buffer, Data1))/binary, Mqtt/binary>>,
            case byte_size(Buf) > ?MAX_HOLD_BUFFER_BYTES of
                true ->
                    stop_with(Data1, hold_overflow);
                false ->
                    hold_bytes(Buf, Data1#{buffer => <<>>})
            end;
        {stop, _, _} = Stop ->
            Stop
    end;

%% --- socket transport normalization (ssl driver support) --------------
%% Plain `ssl' sockets only: `wss' data is claimed by the clauses above
%% and never reaches here.
handle_event(info, {ssl, Sock, Bytes}, State, #{sock := Sock} = Data) ->
    handle_event(info, {tcp, Sock, Bytes}, State, Data);
handle_event(info, {ssl_closed, Sock}, State, #{sock := Sock} = Data) ->
    handle_event(info, {tcp_closed, Sock}, State, Data);
handle_event(info, {ssl_error, Sock, Reason}, State, #{sock := Sock} = Data) ->
    handle_event(info, {tcp_error, Sock, Reason}, State, Data);
handle_event(info, {ssl_passive, Sock}, State, #{sock := Sock} = Data) ->
    handle_event(info, {tcp_passive, Sock}, State, Data);

%% --- counted-active re-arm -------------------------------------------------
%% With `{active, 10}' the socket goes passive after 10 messages; only
%% here (never per message) is it re-armed. The re-arm point also takes
%% the queue-depth sample feeding the pending-bytes gauge, and runs no
%% other housekeeping: this process must get back to draining, not GC.
handle_event(info, {tcp_passive, Sock}, _State, #{sock := Sock} = Data) ->
    arm_socket(Data),
    case catch process_info(self(), message_queue_len) of
        {message_queue_len, N} ->
            catch indra_edge_counters:note_passive(N);
        _ ->
            ok
    end,
    {keep_state, Data};

%% --- client WS bytes: unwrap binary messages to MQTT first -----------
%% A `ws' socket still delivers `{tcp, Sock, Bytes}', but the bytes are
%% WS frames. They decode to MQTT here and then take the exact TCP path
%% below (same CONNECT parsing, same bind metadata, same keepalive), so
%% the kernel sees no difference. WS-level pings never reset the MQTT
%% keepalive timer: only MQTT bytes do. `wss' is identical except the
%% bytes arrive as `{ssl, Sock, Bytes}' (handled above).
handle_event(info, {tcp, Sock, Bytes}, await_connect,
             #{sock := Sock, sockmod := ws} = Data) ->
    case ws_mqtt_bytes(Bytes, Data) of
        {mqtt, <<>>, Data1} ->
            {keep_state, Data1};
        {mqtt, Mqtt, Data1} ->
            Buf = <<(maps:get(buffer, Data1))/binary, Mqtt/binary>>,
            handle_connect_bytes(Buf, Data1#{buffer => <<>>});
        {stop, _, _} = Stop ->
            Stop
    end;
handle_event(info, {tcp, Sock, Bytes}, connected,
             #{sock := Sock, sockmod := ws} = Data) ->
    case ws_mqtt_bytes(Bytes, Data) of
        {mqtt, <<>>, Data1} ->
            {keep_state, Data1};
        {mqtt, Mqtt, Data1} ->
            Buf = <<(maps:get(buffer, Data1))/binary, Mqtt/binary>>,
            handle_connected_bytes(Buf, Data1#{buffer => <<>>});
        {stop, _, _} = Stop ->
            Stop
    end;
handle_event(info, {tcp, Sock, Bytes}, await_core,
             #{sock := Sock, sockmod := ws} = Data) ->
    case ws_mqtt_bytes(Bytes, Data) of
        {mqtt, <<>>, Data1} ->
            {keep_state, Data1};
        {mqtt, Mqtt, Data1} ->
            Buf = <<(maps:get(buffer, Data1))/binary, Mqtt/binary>>,
            case byte_size(Buf) > ?MAX_HOLD_BUFFER_BYTES of
                true ->
                    stop_with(Data1, hold_overflow);
                false ->
                    hold_bytes(Buf, Data1#{buffer => <<>>})
            end;
        {stop, _, _} = Stop ->
            Stop
    end;

%% --- client TCP bytes while awaiting CONNECT --------------------------
%% No per-message re-arm: the socket is counted-active (`{active, 10}'
%% from takeover) and re-armed only at `tcp_passive'.
handle_event(info, {tcp, Sock, Bytes}, await_connect, #{sock := Sock} = Data) ->
    Buf = <<(maps:get(buffer, Data))/binary, Bytes/binary>>,
    handle_connect_bytes(Buf, Data#{buffer => <<>>});
handle_event(info, {tcp_closed, Sock}, _State, #{sock := Sock} = Data) ->
    stop_with(Data, peer_closed);
handle_event(info, {tcp_error, Sock, _Reason}, _State, #{sock := Sock} = Data) ->
    stop_with(Data, tcp_error);

%% --- client TCP bytes while connected: the messaging loop -------------
handle_event(info, {tcp, Sock, Bytes}, connected, #{sock := Sock} = Data) ->
    Buf = <<(maps:get(buffer, Data))/binary, Bytes/binary>>,
    handle_connected_bytes(Buf, Data#{buffer => <<>>});

%% --- client TCP bytes while holding for the core -----------------------
handle_event(info, {tcp, Sock, Bytes}, await_core, #{sock := Sock} = Data) ->
    Buf = <<(maps:get(buffer, Data))/binary, Bytes/binary>>,
    case byte_size(Buf) > ?MAX_HOLD_BUFFER_BYTES of
        true ->
            %% Flood during outage: fail closed, do not balloon.
            stop_with(Data, hold_overflow);
        false ->
            hold_bytes(Buf, Data#{buffer => <<>>})
    end;

%% --- buffered bytes pipelined behind CONNECT ---------------------------
handle_event(internal, drain_buffer, connected, Data) ->
    handle_connected_bytes(maps:get(buffer, Data), Data#{buffer => <<>>});

%% --- fair continuation of a capped egress drain --------------------------
%% `drain_more' arrives through the back of the mailbox (plain
%% `send_after(0, ...)' self-message, not a next_event), so core
%% presence and socket signals that arrived earlier are handled first.
%% Outside `connected' there is nothing to drain: ignore.
handle_event(info, drain_more, connected, Data) ->
    {Queued, Capped} = drain_queued_frames(),
    case Queued of
        [] ->
            {keep_state, Data};
        _ ->
            emit_ordered(Queued, Capped, Data)
    end;

%% --- timers -------------------------------------------------------------
handle_event(state_timeout, connect_timeout, await_connect, Data) ->
    %% Peer never sent CONNECT: do not leak the socket.
    stop_with(Data, connect_timeout);
handle_event(state_timeout, keepalive_timeout, connected, Data) ->
    %% Peer exceeded 1.5 x keepalive without any packet.
    stop_with(Data, keepalive_timeout);

%% --- fallback -------------------------------------------------------------
handle_event(_Type, _Event, _State, Data) ->
    {keep_state, Data}.

terminate(_Reason, _State, #{sock := Sock, sockmod := Mod, conn_id := ConnId} = Data) ->
    %% Attribution that survives the process: the stop cause, the
    %% queued PublishOut frames evaporating with the mailbox (labelled
    %% by QoS), and the QoS 1 publishes accepted but never PUBACKed plus
    %% the QoS 2 publishes accepted but never PUBCOMPd (D1-01, folded
    %% into the same counter so existing dashboards keep working).
    %% Delivery reconciles as: dispatched = received_by_tool +
    %% still_queued + shed_counted + discarded_at_close. Any future
    %% "delivery %" that does not print all four terms is a cutoff
    %% artifact, not a result.
    Cause = maps:get(stop_cause, Data, unknown),
    catch indra_edge_counters:inc(indra_edge_counters:stop_counter(Cause)),
    {DiscQos0, DiscQos1} = drain_close_discards(),
    catch indra_edge_counters:inc(edge_egress_discarded_at_close_qos0_total, DiscQos0),
    catch indra_edge_counters:inc(edge_egress_discarded_at_close_qos1_total, DiscQos1),
    Unacked = map_size(maps:get(pubs_pending, Data, #{}))
        + map_size(maps:get(qos2_pending, Data, #{})),
    catch indra_edge_counters:inc(edge_puback_unacked_at_close_total, Unacked),
    catch indra_edge_counters:credit_delete(ConnId),
    catch indra_conn_registry:unregister(ConnId),
    maybe_signal_unexpected_death(Data),
    catch sock_close(Mod, Sock),
    ok;
terminate(_Reason, _State, _Data) ->
    ok.

%% @private Report an unexpected client death to the kernel (MT-05): a
%% stored CONNECT will must fire exactly once on every death that is not
%% a clean client DISCONNECT nor a kernel-ordered close (connection
%% loss, keepalive timeout, protocol error). A kernel close (kick) already
%% took and fired the will on the kernel side, so no notice follows. The
%% DisconnectIn frame reuses the
%% unbind meta layout (`IdLen | ClientId`); the kernel takes the slot
%% (fire-once) and detaches only on verified ownership, so a stale
%% notice for a superseded connection finds nothing and is harmless.
%% Best-effort and asynchronous: spawned so terminate never
%% blocks on the kernel, and skipped entirely before the handshake bound
%% a client id (nothing could be stored yet).
%% TODO(parity): a notice lost with the edge (the VM halting between the
%% socket close and the send) leaves the will stored until a takeover or
%% reconnect consumes it; the open question is a kernel-side sweep for
%% such orphans.
maybe_signal_unexpected_death(Data) ->
    case maps:get(stop_cause, Data, unknown) of
        client_disconnect ->
            %% Clean DISCONNECT already unbound (will suppressed).
            ok;
        kernel_close ->
            %% Kernel-ordered close (kick): the kernel already took and
            %% fired the will, so no death notice follows (fire-once).
            ok;
        _ ->
            case Data of
                #{broker := Broker, conn_id := ConnId, seq := Seq,
                  client_id := ClientId}
                  when is_pid(Broker), is_binary(ClientId),
                       byte_size(ClientId) > 0 ->
                    Meta = indra_brokerlink:encode_unbind_meta(ClientId),
                    catch spawn(fun() ->
                        catch indra_brokerlink:send(Broker, ?DISCONNECT_IN,
                                                    ConnId, Seq + 1, Meta, <<>>)
                    end),
                    ok;
                _ ->
                    ok
            end
    end.

%%=============================================================%% Socket driver helpers (tcp | ssl | ws | wss)
%%=============================================================
sock_send(gen_tcp, Sock, Bin) -> gen_tcp:send(Sock, Bin);
sock_send(ssl, Sock, Bin) -> ssl:send(Sock, Bin);
sock_send(ws, Sock, Bin) -> gen_tcp:send(Sock, indra_ws:encode_binary(Bin));
sock_send(wss, Sock, Bin) -> ssl:send(Sock, indra_ws:encode_binary(Bin)).

%% @doc Socket options armed on every client connection socket.
%% Counted-active (`{active, 10}'): the socket delivers up to 10
%% messages per re-arm instead of one, so a burst costs no per-message
%% re-arm port call; the re-arm point (see the `tcp_passive' handling)
%% is also where the queue-depth sample is taken. `nodelay' avoids
%% delayed-ACK interaction on small MQTT frames; 64 KiB buffers bound
%% per-connection memory (1M-session scale) while absorbing publish
%% bursts. Backend choice: the default `inet' backend stays. The newer
%% `socket' backend was considered and declined: no measurement on this
%% path implicates the backend (the wall is syscalls per frame plus
%% scheduling, both addressed without it), while switching backends
%% touches every socket site including TLS for an unmeasured gain.
-spec conn_sock_opts() -> [term()].
conn_sock_opts() ->
    [{active, 10}, {nodelay, true}, {recbuf, 65536}, {sndbuf, 65536}].

sock_setopts(gen_tcp, Sock) -> inet:setopts(Sock, conn_sock_opts());
sock_setopts(ssl, Sock) -> ssl:setopts(Sock, conn_sock_opts());
sock_setopts(ws, Sock) -> inet:setopts(Sock, conn_sock_opts());
sock_setopts(wss, Sock) -> ssl:setopts(Sock, conn_sock_opts()).

sock_close(gen_tcp, Sock) -> gen_tcp:close(Sock);
sock_close(ssl, Sock) -> ssl:close(Sock);
sock_close(ws, Sock) -> gen_tcp:close(Sock);
sock_close(wss, Sock) -> ssl:close(Sock).

arm_socket(#{sock := Sock, sockmod := Mod}) ->
    catch sock_setopts(Mod, Sock),
    ok.

%% @private Unwrap WS frames to MQTT bytes. Returns `{mqtt, Bin, Data}'
%% (possibly empty when only control frames arrived), or a stop when a
%% framing violation, a close frame or a pong-send failure ends the
%% connection. Transport pings are answered here and never reach the
%% MQTT layer.
ws_mqtt_bytes(Bytes, Data) ->
    Raw = <<(maps:get(ws_buf, Data, <<>>))/binary, Bytes/binary>>,
    Max = maps:get(ws_max_frame, Data, indra_ws:default_max_frame_bytes()),
    case indra_ws:feed(Raw, maps:get(ws_frag, Data, none), Max) of
        {ok, Events, Rest, Frag} ->
            ws_events(Events, <<>>, Data#{ws_buf => Rest, ws_frag => Frag});
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

ws_events([], Acc, Data) ->
    {mqtt, Acc, Data};
ws_events([{binary, P} | Rest], Acc, Data) ->
    ws_events(Rest, <<Acc/binary, P/binary>>, Data);
ws_events([{pong, _} | Rest], Acc, Data) ->
    ws_events(Rest, Acc, Data);
ws_events([{ping, P} | Rest], Acc, Data) ->
    case ws_transport_send(Data, indra_ws:encode_pong(P)) of
        ok -> ws_events(Rest, Acc, Data);
        {error, _} -> stop_with(bump_send_failed(Data), send_failed)
    end;
ws_events([{close, _} | _], _Acc, Data) ->
    catch ws_transport_send(Data, indra_ws:encode_close()),
    stop_with(Data, peer_closed).

%% @private Send one WS control reply on the connection's own driver
%% (`ws' writes plaintext, `wss' writes on the TLS channel).
ws_transport_send(#{sock := Sock, sockmod := wss}, Bin) ->
    ssl:send(Sock, Bin);
ws_transport_send(#{sock := Sock}, Bin) ->
    gen_tcp:send(Sock, Bin).

%% @private Stop with a recorded cause (read back in terminate/3 for
%% the stop-cause aggregates). Every `{stop, ...}' site in this module
%% goes through here; stuffing the cause into any other return shape
%% would leave deaths unattributed.
%%
%% F1-01: any stop that is not a clean client DISCONNECT
%% (`client_disconnect', which already sent Unbind) nor a kernel-ordered
%% close (`kernel_close', where the kernel already detached) reports an
%% ungraceful close to the kernel via DisconnectIn first, so the stored
%% last will fires. The guard needs only a binary client id (a session
%% exists); handshake states have `undefined' and send nothing. The send
%% is asynchronous (spawned): the socket closes without waiting for the
%% kernel, so a slow or dead kernel never delays the stop (the 5 s
%% subscribe call-timeout kill must stay a 5 s kill, not 5 s plus another
%% 5 s for the notice). A dead kernel simply drops the notice.
stop_with(#{client_id := ClientId, broker := Broker,
            conn_id := ConnId, seq := Seq} = Data, Cause)
  when is_binary(ClientId),
       Cause =/= client_disconnect, Cause =/= kernel_close ->
    case (catch indra_brokerlink:encode_disconnect_meta(ClientId)) of
        <<_/binary>> = Meta ->
            SpawnBroker = Broker,
            SpawnConn = ConnId,
            SpawnSeq = Seq + 1,
            spawn(fun() ->
                catch indra_brokerlink:send(SpawnBroker, ?DISCONNECT_IN,
                                            SpawnConn, SpawnSeq, Meta, <<>>)
            end),
            ok;
        _ ->
            ok
    end,
    {stop, normal, Data#{stop_cause => Cause}};
stop_with(Data, Cause) ->
    {stop, normal, Data#{stop_cause => Cause}}.

%% @private Classify an edge->kernel send failure for attribution. The
%% QoS 0 overload shed never reaches here (it stays up by design); a
%% QoS 1+ kill on `{error, overloaded}' keeps its own cause so the
%% stall-instead-of-kill redesign can see exactly what it removes.
classify_send_error({error, overloaded}) -> ingress_overloaded;
classify_send_error({'EXIT', {timeout, _}}) -> call_timeout;
classify_send_error({'EXIT', _}) -> call_failed;
classify_send_error({error, _}) -> call_failed.

%% @private Count one outbound frame dropped after a client-socket
%% send failure (PERF-10). The connection still stops on the existing
%% path; only the accounting is new.
bump_send_failed(Data) ->
    bump_send_failed(Data, 1).

%% @private Count N outbound frames dropped after a client-socket send
%% failure (the batched write path drops the whole unsent run, not one
%% frame). Each bump also folds into the ETS aggregate so load runs can
%% scrape it without `sys:get_state'.
bump_send_failed(Data, N) ->
    Dropped = maps:get(send_failed_dropped, Data, 0),
    catch indra_edge_counters:inc(edge_egress_send_failed_total, N),
    Data#{send_failed_dropped => Dropped + N}.

%% @doc Drain the queued inbound BrokerLink frames at death and count
%% the PublishOut frames evaporating with the mailbox, labelled by QoS.
%% Returns `{Qos0, Qos1}'. QoS 2 counts with QoS 1 (both need reliability;
%% the counters predate QoS 2). Only matching casts are removed;
%% everything else stays queued and dies with the process. Exported for
%% EUnit (a full connection teardown around it would be timing-flaky);
%% the production caller is terminate/3.
-spec drain_close_discards() -> {non_neg_integer(), non_neg_integer()}.
drain_close_discards() ->
    drain_close_discards(0, 0).

drain_close_discards(Qos0, Qos1) ->
    receive
        {'$gen_cast', {broker_frame, #{opcode := ?PUBLISH_OUT}, Meta, _Payload}} ->
            case catch indra_brokerlink:decode_publish_meta(Meta) of
                {ok, #{qos := 0}} -> drain_close_discards(Qos0 + 1, Qos1);
                {ok, _} -> drain_close_discards(Qos0, Qos1 + 1);
                _ -> drain_close_discards(Qos0, Qos1)
            end
    after 0 ->
        {Qos0, Qos1}
    end.

%%=============================================================%% Handshake helpers
%%=============================================================
handle_connect_bytes(Buf, Data) ->
    case indra_mqtt_codec:decode_packet(Buf) of
        {ok, #{type := 1, payload := Payload}, Rest} ->
            handle_connect_packet(Payload, Rest, Data);
        {ok, #{type := _Other}, _Rest} ->
            %% MQTT 3.1.1 §3.1: first packet MUST be CONNECT.
            stop_with(Data, protocol_error);
        {more, _Need} ->
            {keep_state, Data#{buffer => Buf}};
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

handle_connect_packet(Payload, Rest, #{broker := Broker, conn_id := ConnId, seq := Seq} = Data) ->
    case indra_mqtt_codec:decode_connect(Payload) of
        {ok, #{client_id := ClientId, clean_start := CleanStart, keepalive := Keepalive,
               username := User, password := Pass, will_flag := WillFlag,
               will_qos := WillQos, will_retain := WillRetain,
               will_topic := WillTopic, will_payload := WillPayload} = Conn} ->
            %% The peer address rides the bind so the kernel can refuse
            %% address-banned clients (B1-03); a bind without it simply
            %% matches no address ban, never fails. B4-05: the CONNECT
            %% Topic Alias Maximum rides the bind alias section (the
            %% client's receive limit bounding the kernel outbound
            %% table); 3.1.1 CONNECTs carry none, so the bound stays 0
            %% and deliveries toward them always carry the full topic.
            %% The negotiated level is stashed for CONNACK gating and
            %% PUBLISH decoding below. Table ownership: kernel holds both
            %% tables. F1-01: the CONNECT last will rides the bind when
            %% present; the kernel stores it on the session and publishes
            %% it on an ungraceful close only. A will topic carrying
            %% wildcards (or an empty one) can never route, so the
            %% CONNECT fails closed here instead of registering half
            %% a will.
            %%
            %% B5-05: on a PSK socket the mapped identity is the bind
            %% username, so the kernel authenticates and authorizes it
            %% like any other CONNECT identity (bans, users, quotas all
            %% apply unchanged; the CONNECT password still rides along
            %% for the kernel to verify). A CONNECT username that is
            %% neither absent nor identical fails closed here with no
            %% bind sent.
            %% TODO(parity): the spec does not decide whether a
            %% mismatched CONNECT username should close (current,
            %% conservative) or be ignored in favour of the PSK
            %% identity; confirm the intended policy.
            ProtoLevel = maps:get(protocol_level, Conn, 4),
            ClientAliasMax = maps:get(alias_max, Conn, 0),
            %% X1-01: a version-5 CONNECT carries the negotiated version
            %% plus the decoded properties the kernel needs (session
            %% expiry, receive maximum, maximum packet size, client
            %% user-properties) in the bind v5 section (/9); a
            %% version-4 CONNECT encodes exactly like before (/9 with
            %% `undefined' is byte-identical to /8).
            V5Info = make_v5_info(ProtoLevel, Conn),
            case psk_username(maps:get(psk_identity, Data, undefined), User) of
                {error, _} ->
                    stop_with(Data, protocol_error);
                {ok, MappedUser} ->
                    case make_will(WillFlag, WillTopic, WillPayload, WillQos, WillRetain) of
                        {error, _} ->
                            stop_with(Data, protocol_error);
                        {ok, Will} ->
                            %% Canonical SY-02 encoding carries alias maximum,
                            %% certificate fields and will together (/8); a WebSocket
                            %% connection gets PSK, will and alias handling exactly
                            %% as TCP does. X1-01 appends the v5 section (/9).
                            Meta = (catch indra_brokerlink:encode_bind_meta(
                                         ClientId, CleanStart, Keepalive,
                                         {MappedUser, Pass},
                                         peer_ip_opt(Data), ClientAliasMax,
                                         cert_info_opt(Data), Will, V5Info)),
                            case Meta of
                                <<_/binary>> ->
                                    case catch indra_brokerlink:send(Broker, ?BIND_CONNECTION,
                                                                      ConnId, Seq + 1, Meta, <<>>) of
                                        ok ->
                                            Pending = #{client_id => ClientId,
                                                        keepalive => Keepalive,
                                                        will => Will,
                                                        proto_level => ProtoLevel,
                                                        client_alias_max => ClientAliasMax,
                                                        v5_info => V5Info,
                                                        username => MappedUser,
                                                        password => Pass},
                                            %% Stash bytes pipelined behind CONNECT; they drain once
                                            %% the handshake completes (see `drain_buffer`).
                                            {keep_state, Data#{seq => Seq + 1,
                                                               pending => Pending,
                                                               buffer => Rest}};
                                        Other ->
                                            stop_with(Data, classify_send_error(Other))
                                    end;
                                _ ->
                                    %% Will too large for the bind meta (or another
                                    %% encoding refusal): fail closed, no half bind.
                                    stop_with(Data, protocol_error)
                            end
                    end
            end;
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

%% @private Build the bind v5 section from a decoded CONNECT (X1-01).
%% Version 4 (and anything older) carries no v5 section: `undefined'
%% encodes exactly like the /8 bind, byte-identical to before. Version
%% 5 carries the negotiated version plus the CONNECT properties the
%% kernel needs; the kernel owns their session semantics (X1-02), the
%% edge only frames and transports them.
make_v5_info(5, Conn) ->
    #{version => 5,
      session_expiry => maps:get(session_expiry, Conn, 0),
      receive_max => maps:get(receive_max, Conn, 65535),
      max_packet_size => maps:get(max_packet_size, Conn, 0),
      user_properties => maps:get(user_properties, Conn, [])};
make_v5_info(_, _) ->
    undefined.

%% @private CONNACK v5 properties for the live handshake path (X1-02).
%% The kernel binding carries the negotiated session state: the
%% inbound alias maximum, the granted session expiry, the server
%% receive-maximum / maximum-packet-size limits, the server-side
%% reason string and the echoed CONNECT user properties. Each rides
%% only when meaningful (nonzero maxima/expiry, non-empty reason and
%% user list); the codec omits the rest, so success CONNACKs carry
%% session-present plus the assigned values and server limits while
%% failure CONNACKs carry the reason code plus the reason string and
%% the echoed properties. Version-4 sockets never reach here (they
%% take the folded 4-byte shape).
v5_connack_opts(Binding) when is_map(Binding) ->
    AliasMax = maps:get(alias_max, Binding, 0),
    RecvMax = maps:get(server_recv_max, Binding, 0),
    MaxPkt = maps:get(server_max_pkt, Binding, 0),
    Expiry = maps:get(session_expiry, Binding, 0),
    Reason = maps:get(reason_string, Binding, <<>>),
    Users = maps:get(user_properties, Binding, []),
    Base = #{user_properties => Users},
    WithAlias = case AliasMax of
        N when is_integer(N), N >= 1 -> Base#{alias_max => N};
        _ -> Base
    end,
    WithRecv = case RecvMax of
        R when is_integer(R), R >= 1 -> WithAlias#{receive_max => R};
        _ -> WithAlias
    end,
    WithPkt = case MaxPkt of
        P when is_integer(P), P >= 1 -> WithRecv#{max_packet_size => P};
        _ -> WithRecv
    end,
    WithExpiry = case Expiry of
        E when is_integer(E), E >= 1 -> WithPkt#{session_expiry => E};
        _ -> WithPkt
    end,
    case Reason of
        <<>> -> WithExpiry;
        RS when is_binary(RS), byte_size(RS) >= 1 -> WithExpiry#{reason_string => RS};
        _ -> WithExpiry
    end.

%% @private Map the TLS PSK identity onto the bind username (B5-05).
%% Plaintext and certificate sockets carry `undefined' and keep the
%% CONNECT username untouched. On a PSK socket an absent CONNECT
%% username defaults to the identity and an identical one is accepted;
%% anything else fails closed (no bind is sent, the socket closes).
-spec psk_username(binary() | undefined, binary() | undefined) ->
    {ok, binary() | undefined} | {error, psk_identity_mismatch}.
psk_username(undefined, User) ->
    {ok, User};
psk_username(PskId, undefined) ->
    {ok, PskId};
psk_username(PskId, PskId) ->
    {ok, PskId};
psk_username(_, _) ->
    {error, psk_identity_mismatch}.

%% @private Build the bind will from decoded CONNECT fields. `undefined'
%% when the will flag is clear; otherwise the topic must be routable
%% (non-empty, no wildcards) and the payload a binary (empty allowed).
make_will(false, _, _, _, _) ->
    {ok, undefined};
make_will(true, Topic, Payload, QoS, Retain)
  when is_binary(Topic), is_binary(Payload),
       (QoS =:= 0 orelse QoS =:= 1 orelse QoS =:= 2),
       (Retain =:= true orelse Retain =:= false),
       byte_size(Topic) >= 1 ->
    case binary:match(Topic, [<<"+">>, <<"#">>]) of
        nomatch ->
            {ok, #{topic => Topic, payload => Payload,
                   qos => QoS, retain => Retain}};
        _ ->
            {error, invalid_will_topic}
    end;
make_will(_, _, _, _, _) ->
    {error, invalid_will_topic}.

%% @private Re-send the pending bind to a replacement broker (core flap
%% mid-handshake). Drops back to waiting on failure. The pending will
%% rides along: the first bind never completed, so without it the
%% kernel would register the session with no will.
resend_bind(#{broker := Broker, conn_id := ConnId, seq := Seq,
               pending := #{client_id := ClientId, keepalive := Keepalive} = Pending} = Data) ->
    Will = maps:get(will, Pending, undefined),
    ClientAliasMax = maps:get(client_alias_max, Pending, 0),
    Username = maps:get(username, Pending, undefined),
    Password = maps:get(password, Pending, undefined),
    %% X1-01: the pending v5 section re-rides the rebind (the first
    %% bind never completed); `undefined' on version-4 handshakes keeps
    %% the encoding byte-identical to before.
    V5Info = maps:get(v5_info, Pending, undefined),
    Meta = case Will of
        undefined ->
            (catch indra_brokerlink:encode_bind_meta(ClientId, false, Keepalive,
                                                     {Username, Password},
                                                     peer_ip_opt(Data), ClientAliasMax,
                                             cert_info_opt(Data), undefined, V5Info));
        _ ->
            (catch indra_brokerlink:encode_bind_meta(ClientId, false, Keepalive,
                                                     {Username, Password},
                                                     peer_ip_opt(Data), ClientAliasMax,
                                             cert_info_opt(Data), Will, V5Info))
    end,
    case Meta of
        <<_/binary>> ->
            case catch indra_brokerlink:send(Broker, ?BIND_CONNECTION, ConnId, Seq + 1, Meta, <<>>) of
                ok ->
                    {keep_state, Data#{seq => Seq + 1}};
                _ ->
                    {keep_state, Data}
            end;
        _ ->
            {keep_state, Data}
    end;
resend_bind(Data) ->
    {keep_state, Data}.

%% @private Client IP literal for the bind peer section (B1-03): the
%% address the client socket came from, so the kernel can refuse
%% address-banned clients. `undefined' when the socket is gone or the
%% address cannot be read; the kernel then matches no address ban for
%% this bind instead of failing it.
peer_ip_opt(#{sock := Sock, sockmod := SockMod}) ->
    peer_ip(Sock, SockMod);
peer_ip_opt(_) ->
    undefined.

peer_ip(Sock, gen_tcp) ->
    case catch inet:peername(Sock) of
        {ok, {IP, _Port}} ->
            list_to_binary(inet:ntoa(IP));
        _ ->
            undefined
    end;
peer_ip(Sock, ssl) ->
    case catch ssl:peername(Sock) of
        {ok, {IP, _Port}} ->
            list_to_binary(inet:ntoa(IP));
        _ ->
            undefined
    end;
peer_ip(Sock, ws) ->
    %% A WS socket is a plaintext TCP socket past the upgrade: the peer
    %% is the TCP peer, exactly as for `gen_tcp'.
    case catch inet:peername(Sock) of
        {ok, {IP, _Port}} ->
            list_to_binary(inet:ntoa(IP));
        _ ->
            undefined
    end;
peer_ip(Sock, wss) ->
    %% A WSS socket is a TLS socket past the upgrade: the peer is the
    %% TLS peer, exactly as for `ssl'.
    case catch ssl:peername(Sock) of
        {ok, {IP, _Port}} ->
            list_to_binary(inet:ntoa(IP));
        _ ->
            undefined
    end;
peer_ip(_, _) ->
    undefined.

%% @private TLS client-certificate fields for the bind certificate
%% section (MT-01): the common name, subject and subject-alt names the
%% edge extracted where TLS terminates. `undefined' on plaintext
%% transports or when no client certificate was presented; the kernel
%% then assigns the default tenant instead of failing the bind. A
%% certificate that cannot be parsed also forwards as absent (fail
%% closed to the default tenant, never to another tenant's).
cert_info_opt(#{sock := Sock, sockmod := SockMod}) ->
    cert_info(Sock, SockMod);
cert_info_opt(_) ->
    undefined.

cert_info(Sock, ssl) ->
    peer_cert_info(Sock);
cert_info(Sock, wss) ->
    %% A WSS socket is a TLS socket past the upgrade: the client
    %% certificate is the TLS peer certificate, exactly as for `ssl'.
    peer_cert_info(Sock);
cert_info(_, _) ->
    undefined.

peer_cert_info(Sock) ->
    case catch ssl:peercert(Sock) of
        {ok, Der} ->
            parse_cert_info(Der);
        _ ->
            undefined
    end.

parse_cert_info(Der) when is_binary(Der) ->
    case catch public_key:pkix_decode_cert(Der, otp) of
        {'OTPCertificate', Tbs, _, _} ->
            cert_from_tbs(Tbs);
        _ ->
            undefined
    end;
parse_cert_info(_) ->
    undefined.

cert_from_tbs(Tbs) ->
    try
        %% OTPTBSCertificate layout: 1 = record name, 2 = version,
        %% 3 = serial, 4 = signature, 5 = issuer, 6 = validity,
        %% 7 = subject, 8 = public key, 9-10 = unique ids,
        %% 11 = extensions.
        Subject = element(7, Tbs),
        Extensions = cert_extensions(Tbs),
        Cn = cert_common_name(Subject),
        Sans = cert_alt_names(Extensions),
        #{cn => Cn, subject => cert_subject_bin(Subject), sans => Sans}
    catch
        _:_ ->
            undefined
    end.

%% @private Certificate extensions (position 11 of OTPTBSCertificate),
%% `undefined' when absent.
cert_extensions(Tbs) ->
    case catch element(11, Tbs) of
        {'asn1_NOVALUE', _} -> undefined;
        asn1_NOVALUE -> undefined;
        undefined -> undefined;
        Extensions -> Extensions
    end.

%% @private First commonName attribute of the subject, if any.
cert_common_name({rdnSequence, Rdns}) ->
    find_cn(Rdns);
cert_common_name(_) ->
    undefined.

find_cn([]) ->
    undefined;
find_cn([[{'AttributeTypeAndValue', Oid, Value} | _] | Rest]) ->
    case is_cn_oid(Oid) of
        true -> cert_value_bin(Value);
        false -> find_cn(Rest)
    end;
find_cn([Rdn | Rest]) when is_list(Rdn) ->
    case find_cn_in_rdn(Rdn) of
        undefined -> find_cn(Rest);
        Found -> Found
    end;
find_cn([_ | Rest]) ->
    find_cn(Rest).

find_cn_in_rdn([]) ->
    undefined;
find_cn_in_rdn([{'AttributeTypeAndValue', Oid, Value} | _])
  when is_tuple(Oid) ->
    case is_cn_oid(Oid) of
        true -> cert_value_bin(Value);
        false -> undefined
    end;
find_cn_in_rdn([_ | Rest]) ->
    find_cn_in_rdn(Rest).

%% @private OID 2.5.4.3 is commonName.
is_cn_oid({2, 5, 4, 3}) -> true;
is_cn_oid(_) -> false.

%% @private Subject distinguished name rendered as a slash-separated
%% binary (`/CN=../O=..'); `undefined' when it cannot be rendered.
cert_subject_bin({rdnSequence, Rdns}) ->
    try
        Parts = lists:flatmap(fun cert_rdn_parts/1, Rdns),
        case Parts of
            [] -> undefined;
            _ -> list_to_binary([$/ | lists:join($/, Parts)])
        end
    catch
        _:_ -> undefined
    end;
cert_subject_bin(_) ->
    undefined.

cert_rdn_parts(Rdn) when is_list(Rdn) ->
    lists:filtermap(
      fun({'AttributeTypeAndValue', Oid, Value}) when is_tuple(Oid) ->
              case {catch cert_attr_name(Oid), catch cert_value_bin(Value)} of
                  {Name, Bin} when is_list(Name), is_binary(Bin) ->
                      {true, Name ++ "=" ++ binary_to_list(Bin)};
                  _ ->
                      false
              end;
         (_) ->
              false
      end, Rdn);
cert_rdn_parts(_) ->
    [].

cert_attr_name({2, 5, 4, 3}) -> "CN";
cert_attr_name({2, 5, 4, 10}) -> "O";
cert_attr_name({2, 5, 4, 11}) -> "OU";
cert_attr_name({2, 5, 4, 7}) -> "L";
cert_attr_name({2, 5, 4, 8}) -> "ST";
cert_attr_name({2, 5, 4, 6}) -> "C";
cert_attr_name(_) -> erlang:error(badattr).

cert_value_bin({utf8String, Bin}) when is_binary(Bin) -> Bin;
cert_value_bin({printableString, Chars}) -> list_to_binary(Chars);
cert_value_bin({teletexString, Bin}) when is_binary(Bin) -> Bin;
cert_value_bin({ia5String, Bin}) when is_binary(Bin) -> Bin;
cert_value_bin(Bin) when is_binary(Bin) -> Bin;
cert_value_bin(Chars) when is_list(Chars) -> list_to_binary(Chars);
cert_value_bin(_) -> erlang:error(badvalue).

%% @private Subject-alt names (dNSName and iPAddress entries only) from
%% the extension list; anything unparsable yields no SANs (fail closed
%% to fewer inputs, never to a wrong tenant).
cert_alt_names(undefined) ->
    [];
cert_alt_names(Extensions) when is_list(Extensions) ->
    lists:flatmap(fun cert_alt_names_ext/1, Extensions);
cert_alt_names(_) ->
    [].

cert_alt_names_ext({'Extension', {2, 5, 29, 17}, _, AltNames}) when is_list(AltNames) ->
    lists:filtermap(fun san_bin/1, AltNames);
cert_alt_names_ext(_) ->
    [].

%% @private One subject-alt name as a binary. dNSName rides verbatim;
%% iPAddress rides as raw bytes (4 or 16) or as a tuple and is rendered
%% with `inet:ntoa/1'. Anything else (URIs, other names, malformed
%% entries) is skipped: fewer inputs fail closed to the default tenant,
%% never to a wrong one, and one bad SAN never drops the whole cert.
san_bin({dNSName, Name}) when is_list(Name) ->
    {true, list_to_binary(Name)};
san_bin({dNSName, Name}) when is_binary(Name) ->
    {true, Name};
san_bin({iPAddress, {_, _, _, _} = Ip}) ->
    {true, list_to_binary(inet:ntoa(Ip))};
san_bin({iPAddress, {_, _, _, _, _, _, _, _} = Ip}) ->
    {true, list_to_binary(inet:ntoa(Ip))};
san_bin({iPAddress, <<A, B, C, D>>}) ->
    {true, list_to_binary(inet:ntoa({A, B, C, D}))};
san_bin({iPAddress, <<A:16/big, B:16/big, C:16/big, D:16/big,
                      E:16/big, F:16/big, G:16/big, H:16/big>>}) ->
    {true, list_to_binary(inet:ntoa({A, B, C, D, E, F, G, H}))};
san_bin(_) ->
    false.

handle_session_binding(Meta, #{sock := Sock, sockmod := Mod} = Data) ->
    case indra_brokerlink:decode_session_binding_meta(Meta) of
        %% B4-05: the binding carries the kernel inbound alias maximum for
        %% CONNACK negotiation. MQTT 5 peers learn it through the CONNACK
        %% property (34) via the v5 encoder; 3.1.1 peers always get the
        %% 4-byte encode_connack/2 shape (a property section would break
        %% their framing), so alias_max 0 and every level-4 socket encode
        %% with no property. Fail closed: a client never sends aliases it
        %% was never told about. Table ownership: kernel holds both
        %% tables; the edge only frames the wire values.
        %% X1-01: version-5 connections get a v5 CONNACK (acknowledge
        %% flags + raw v5 reason code + properties) used only on those
        %% sockets; version-4 behaviour (folded return codes, fixed
        %% 4-byte shape) is unchanged.
        %% X1-02: the v5 binding section carries the granted session
        %% expiry, the server receive-maximum / maximum-packet-size
        %% limits, the server-side reason string and the echoed CONNECT
        %% user properties; success CONNACKs advertise the assigned
        %% values and server limits, failure CONNACKs the reason code
        %% plus the reason string and echoed properties.
        {ok, #{session_id := SessionId,
               session_present := Present,
               return_code := RC} = Binding} ->
            Pending0 = maps:get(pending, Data, #{client_id => <<>>,
                                                 keepalive => 0}),
            ProtoLevel = maps:get(proto_level, Pending0, 4),
            Connack = case ProtoLevel of
                5 ->
                    indra_mqtt_codec:encode_connack_v5(
                      Present, RC, v5_connack_opts(Binding));
                _ ->
                    %% Version 4 always gets the fixed 4-byte shape: a
                    %% property section would break 3.1.1 framing, even
                    %% when the kernel advertises an inbound alias
                    %% maximum (3.1.1 peers never use aliases).
                    indra_mqtt_codec:encode_connack(
                      Present, indra_mqtt_codec:connack_return_code(RC))
            end,
            case sock_send(Mod, Sock, Connack) of
                ok when RC =:= 0 ->
                    Pending = Pending0,
                    Data1 = Data#{session_id => SessionId,
                                  client_id => maps:get(client_id, Pending, <<>>),
                                  keepalive => maps:get(keepalive, Pending, 0),
                                  will => maps:get(will, Pending, undefined),
                                  proto_level => ProtoLevel,
                                  v5_info => maps:get(v5_info, Pending, undefined),
                                  client_alias_max =>
                                      maps:get(client_alias_max, Pending, 0)},
                    {next_state, connected, Data1,
                     [keepalive_action(Data1), {next_event, internal, drain_buffer}]};
                ok ->
                    %% Rejected (RC /= 0): CONNACK delivered, just close.
                    %% The kernel ordered this close (bind rejection), so
                    %% it is attributed as a kernel close.
                    stop_with(Data, kernel_close);
                {error, _} ->
                    %% CONNACK never reached the peer: counted drop.
                    stop_with(bump_send_failed(Data), send_failed)
            end;
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

%%=============================================================%% Core holding + rebind (Sprint 11 restart immunity)
%%=============================================================
%% @private Begin recovery: re-bind the session, always non-clean so a
%% surviving core resumes (present=true, offline replay follows) while a
%% fresh core simply recreates. Core-side tracking resets; the client
%% buffer is preserved for the post-rebind drain. The stored last will
%% re-rides the rebind so a fresh core re-registers it.
start_rebind(#{broker := Broker, conn_id := ConnId, seq := Seq,
               client_id := ClientId, keepalive := Keepalive} = Data)
  when is_binary(ClientId) ->
    Will = maps:get(will, Data, undefined),
    ClientAliasMax = maps:get(client_alias_max, Data, 0),
    %% X1-01: the stored v5 section re-rides the rebind so the kernel
    %% outbound table and session properties survive core restarts;
    %% `undefined' on version-4 connections keeps the encoding
    %% byte-identical to before.
    V5Info = maps:get(v5_info, Data, undefined),
    Meta = case Will of
        undefined ->
            (catch indra_brokerlink:encode_bind_meta(ClientId, false, Keepalive,
                                                     {undefined, undefined},
                                                     peer_ip_opt(Data), ClientAliasMax,
                                             cert_info_opt(Data), undefined, V5Info));
        _ ->
            (catch indra_brokerlink:encode_bind_meta(ClientId, false, Keepalive,
                                                     {undefined, undefined},
                                                     peer_ip_opt(Data), ClientAliasMax,
                                             cert_info_opt(Data), Will, V5Info))
    end,
    case Meta of
        <<_/binary>> ->
            case catch indra_brokerlink:send(Broker, ?BIND_CONNECTION, ConnId, Seq + 1, Meta, <<>>) of
                ok ->
                    {next_state, await_core, Data#{seq => Seq + 1,
                                                   subs_pending => #{},
                                                   pubs_pending => #{},
                                                   qos2_pending => #{},
                                                   quiet_subs => #{},
                                                   rebinding => true}};
                _ ->
                    %% Replacement core already gone: hold for the next sweep.
                    {next_state, await_core, Data#{rebinding => false}}
            end;
        _ ->
            {next_state, await_core, Data#{rebinding => false}}
    end;
start_rebind(Data) ->
    %% No established session (should not happen): hold.
    {next_state, await_core, Data}.

%% @private Rebind answer: no CONNACK (already sent at first connect).
%% When the core lost state it re-registers every tracked subscription
%% silently (their SubAcks are swallowed, never re-sent to the client).
handle_rebind_binding(Meta, Data) ->
    case indra_brokerlink:decode_session_binding_meta(Meta) of
        {ok, #{session_id := SessionId, session_present := Present,
               return_code := 0}} ->
            Data1 = Data#{session_id => SessionId, rebinding => false},
            case Present of
                true ->
                    {next_state, connected, Data1,
                     [keepalive_action(Data1), {next_event, internal, drain_buffer}]};
                false ->
                    case resubscribe_all(Data1) of
                        {ok, Data2} ->
                            {next_state, connected, Data2,
                             [keepalive_action(Data2),
                              {next_event, internal, drain_buffer}]};
                        {hold, Data2} ->
                            %% Broker flapped mid-resubscribe: hold for the
                            %% next sweep instead of dropping the client.
                            {next_state, await_core, Data2}
                    end
            end;
        _ ->
            stop_with(Data, kernel_close)
    end.

%% @private Re-register every tracked subscription; answers land in
%% `quiet_subs` and are swallowed on arrival.
resubscribe_all(#{subs := Subs, broker := Broker, conn_id := ConnId,
                  seq := Seq, client_id := ClientId} = Data) ->
    try
        Seq1 = maps:fold(
            fun(Filter, {QoS, PacketId}, SAcc) ->
                Meta = indra_brokerlink:encode_subscribe_meta(PacketId, ClientId,
                                                              [{Filter, QoS}]),
                ok = indra_brokerlink:send(Broker, ?SUBSCRIBE_IN, ConnId, SAcc + 1,
                                           Meta, <<>>),
                SAcc + 1
            end, Seq, Subs),
        Quiet = maps:fold(
            fun(_Filter, {_QoS, PacketId}, Acc) -> Acc#{PacketId => true} end,
            #{}, Subs),
        {ok, Data#{seq => Seq1, quiet_subs => Quiet}}
    catch
        _:_ ->
            {hold, Data#{rebinding => false}}
    end.

%% @private Hold client bytes while the core is down: answer PINGREQ so
%% the peer keepalive survives the outage, buffer everything else for
%% the post-rebind drain.
hold_bytes(Buf, Data) ->
    hold_scan(Buf, Data, <<>>).

hold_scan(<<>>, Data, Held) ->
    {keep_state, Data#{buffer => Held}};
hold_scan(Buf, #{sock := Sock, sockmod := Mod} = Data, Held) ->
    case indra_mqtt_codec:decode_packet(Buf) of
        {ok, #{type := 12}, Rest} ->
            case sock_send(Mod, Sock, <<16#D0, 16#00>>) of
                ok -> hold_scan(Rest, Data, Held);
                {error, _} -> stop_with(bump_send_failed(Data), send_failed)
            end;
        {ok, _Other, Rest} ->
            %% Stash this packet's bytes, keep scanning for pings.
            Used = byte_size(Buf) - byte_size(Rest),
            <<This:Used/binary, _/binary>> = Buf,
            hold_scan(Rest, Data, <<Held/binary, This/binary>>);
        {more, _Need} ->
            {keep_state, Data#{buffer => <<Held/binary, Buf/binary>>}};
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

%%=============================================================%% Connected messaging loop
%%=============================================================
%% @private Drain one or more client packets; any handled packet resets
%% the keepalive timer.
handle_connected_bytes(<<>>, Data) ->
    {keep_state, Data, [keepalive_action(Data)]};
handle_connected_bytes(Buf, Data) ->
    case indra_mqtt_codec:decode_packet(Buf) of
        {ok, Packet, Rest} ->
            case handle_mqtt_packet(Packet, Data) of
                {ok, Data1} ->
                    handle_connected_bytes(Rest, Data1);
                {stop, _, _} = Stop ->
                    Stop
            end;
        {more, _Need} ->
            {keep_state, Data#{buffer => Buf}, [keepalive_action(Data)]};
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

%% @private Handle one decoded client packet. Returns `{ok, Data}` to
%% continue or a `stop_with/2' stop to close the connection.
handle_mqtt_packet(#{type := 8, payload := Payload}, Data) ->
    handle_subscribe_packet(Payload, Data);
handle_mqtt_packet(#{type := 3, flags := Flags, payload := Payload}, Data) ->
    handle_publish_packet(Payload, Flags, Data);
handle_mqtt_packet(#{type := 12}, #{sock := Sock, sockmod := Mod} = Data) ->
    %% Fast edge PINGRESP; any packet resets keepalive via the caller.
    case sock_send(Mod, Sock, <<16#D0, 16#00>>) of
        ok -> {ok, Data};
        {error, _} -> stop_with(bump_send_failed(Data), send_failed)
    end;
handle_mqtt_packet(#{type := 14}, Data) ->
    handle_disconnect(Data);
handle_mqtt_packet(#{type := 4, payload := Payload}, Data) ->
    %% Inbound PUBACK for a QoS 1 downstream delivery: forward the
    %% packet id to the kernel (PubAckIn) so it releases the matching
    %% per-session inflight entry (T-31). Malformed ids are ignored;
    %% a failed forward keeps the connection up (the kernel simply
    %% replays on reconnect).
    handle_puback_in(Payload, Data);
handle_mqtt_packet(#{type := 5, payload := Payload}, Data) ->
    %% Inbound PUBREC for a QoS 2 downstream delivery (D1-01): forward
    %% as PubRecIn so the kernel sends PUBREL. Malformed ids ignored.
    handle_pubrec_in(Payload, Data);
handle_mqtt_packet(#{type := 6, payload := Payload}, Data) ->
    %% Inbound PUBREL for a QoS 2 upstream publish (D1-01): forward as
    %% PubRelIn so the kernel routes once and replies PUBCOMP.
    handle_pubrel_in(Payload, Data);
handle_mqtt_packet(#{type := 7, payload := Payload}, Data) ->
    %% Inbound PUBCOMP for a QoS 2 downstream delivery (D1-01): forward
    %% as PubCompIn so the kernel releases the packet id.
    handle_pubcomp_in(Payload, Data);
handle_mqtt_packet(_Other, Data) ->
    %% CONNECT repeats, CONNACK/SUBACK from a client, UNSUBSCRIBE and any
    %% other unexpected packet: protocol violation, close.
    stop_with(Data, protocol_error).

handle_subscribe_packet(Payload, Data) ->
    case indra_mqtt_codec:decode_subscribe(Payload) of
        {ok, #{packet_id := PacketId, subscriptions := Subs}} ->
            #{broker := Broker, conn_id := ConnId, seq := Seq,
              client_id := ClientId, subs_pending := Pending,
              subs := Tracked} = Data,
            Meta = indra_brokerlink:encode_subscribe_meta(PacketId, ClientId, Subs),
            case catch indra_brokerlink:send(Broker, ?SUBSCRIBE_IN, ConnId, Seq + 1, Meta, <<>>) of
                ok ->
                    Tracked1 = lists:foldl(
                        fun({Filter, QoS}, Acc) -> Acc#{Filter => {QoS, PacketId}} end,
                        Tracked, Subs),
                    {ok, Data#{seq => Seq + 1,
                               subs_pending => Pending#{PacketId => true},
                               subs => Tracked1}};
                Other ->
                    stop_with(Data, classify_send_error(Other))
            end;
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

handle_publish_packet(Payload, Flags, Data) ->
    ProtoLevel = maps:get(proto_level, Data, 4),
    case indra_mqtt_codec:decode_publish(Payload, Flags, ProtoLevel) of
        {ok, #{topic := Topic, packet_id := PacketId, qos := QoS,
               retain := Retain, dup := Dup, payload := AppPayload,
               alias := Alias, alias_present := AliasPresent}} ->
            #{broker := Broker, conn_id := ConnId, seq := Seq,
              pubs_pending := Pending, qos2_pending := Qos2Pending} = Data,
            %% B4-05: the alias rides the PUBLISH alias property on v5
            %% sockets (absent on 3.1.1, where the codec always reports
            %% it absent). Forward absent via the /5 form, never an
            %% explicit alias 0 section: absent means "no alias carried"
            %% while an explicit 0 is a protocol error the kernel
            %% rejects with DISCONNECT 0x94, and the two must stay
            %% distinguishable on the wire. The kernel checks the alias
            %% against the CONNACK-negotiated maximum on the PUBLISH
            %% event, where the inbound table is written.
            Meta = case AliasPresent of
                false ->
                    indra_brokerlink:encode_publish_meta(Topic, PacketId, QoS, Retain, Dup);
                true ->
                    indra_brokerlink:encode_publish_meta(Topic, PacketId, QoS, Retain, Dup,
                                                         Alias)
            end,
            case catch indra_brokerlink:send(Broker, ?PUBLISH_IN, ConnId, Seq + 1, Meta, AppPayload) of
                ok when QoS =:= 1 ->
                    {ok, Data#{seq => Seq + 1,
                               pubs_pending => Pending#{PacketId => true}}};
                ok when QoS =:= 2 ->
                    {ok, Data#{seq => Seq + 1,
                               qos2_pending => Qos2Pending#{PacketId => true}}};
                ok ->
                    {ok, Data#{seq => Seq + 1}};
                %% PERF-09 bounded ingress: the owning shard is past
                %% its bound. Shed this QoS 0 publish with a counted
                %% drop; the connection stays up. QoS 1 keeps its
                %% existing semantics (no silent drops: any failure,
                %% including overload, still closes).
                {error, overloaded} when QoS =:= 0 ->
                    Dropped = maps:get(qos0_dropped, Data, 0),
                    catch indra_edge_counters:inc(edge_ingress_qos0_shed_total),
                    {ok, Data#{qos0_dropped => Dropped + 1}};
                Other ->
                    stop_with(Data, classify_send_error(Other))
            end;
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

handle_disconnect(#{broker := Broker, conn_id := ConnId, seq := Seq,
                    client_id := ClientId} = Data) ->
    %% Fire-and-forget unbind: the socket closes regardless.
    Meta = indra_brokerlink:encode_unbind_meta(ClientId),
    catch indra_brokerlink:send(Broker, ?UNBIND_CONNECTION, ConnId, Seq + 1, Meta, <<>>),
    stop_with(Data, client_disconnect).

%% @private Forward one subscriber PUBACK to the kernel so it releases
%% the matching inflight entry (T-31). The kernel owns the store; the
%% edge only reports. Malformed payloads are ignored.
handle_puback_in(<<PacketId:16/big>>, #{broker := Broker, conn_id := ConnId,
                                        seq := Seq} = Data)
  when PacketId =/= 0 ->
    Meta = indra_brokerlink:encode_puback_meta(PacketId, 0),
    case catch indra_brokerlink:send(Broker, ?PUBACK_IN, ConnId, Seq + 1, Meta, <<>>) of
        ok ->
            {ok, Data#{seq => Seq + 1}};
        {error, overloaded} ->
            %% Shedding an ack only delays its release: the kernel
            %% replays on reconnect, preserving at-least-once.
            {ok, Data};
        Other ->
            stop_with(Data, classify_send_error(Other))
    end;
handle_puback_in(_, Data) ->
    {ok, Data}.

%% @private Forward one subscriber PUBREC to the kernel (D1-01 outbound:
%% the kernel answers with PUBREL). Malformed ids are ignored; a failed
%% forward keeps the connection up (the kernel replays PUBLISH on
%% reconnect, preserving exactly-once).
handle_pubrec_in(<<PacketId:16/big>>, #{broker := Broker, conn_id := ConnId,
                                        seq := Seq} = Data)
  when PacketId =/= 0 ->
    Meta = indra_brokerlink:encode_pubrec_meta(PacketId),
    case catch indra_brokerlink:send(Broker, ?PUBREC_IN, ConnId, Seq + 1, Meta, <<>>) of
        ok ->
            {ok, Data#{seq => Seq + 1}};
        {error, overloaded} ->
            {ok, Data};
        Other ->
            stop_with(Data, classify_send_error(Other))
    end;
handle_pubrec_in(_, Data) ->
    {ok, Data}.

%% @private Forward one publisher PUBREL to the kernel (D1-01 inbound:
%% the kernel routes once and replies PUBCOMP). Malformed ids ignored.
handle_pubrel_in(<<PacketId:16/big>>, #{broker := Broker, conn_id := ConnId,
                                        seq := Seq} = Data)
  when PacketId =/= 0 ->
    Meta = indra_brokerlink:encode_pubrel_meta(PacketId),
    case catch indra_brokerlink:send(Broker, ?PUBREL_IN, ConnId, Seq + 1, Meta, <<>>) of
        ok ->
            {ok, Data#{seq => Seq + 1}};
        {error, overloaded} ->
            {ok, Data};
        Other ->
            stop_with(Data, classify_send_error(Other))
    end;
handle_pubrel_in(_, Data) ->
    {ok, Data}.

%% @private Forward one subscriber PUBCOMP to the kernel (D1-01 outbound
%% completion: the kernel releases the packet id). Malformed ids ignored.
handle_pubcomp_in(<<PacketId:16/big>>, #{broker := Broker, conn_id := ConnId,
                                         seq := Seq} = Data)
  when PacketId =/= 0 ->
    Meta = indra_brokerlink:encode_pubcomp_meta(PacketId),
    case catch indra_brokerlink:send(Broker, ?PUBCOMP_IN, ConnId, Seq + 1, Meta, <<>>) of
        ok ->
            {ok, Data#{seq => Seq + 1}};
        {error, overloaded} ->
            {ok, Data};
        Other ->
            stop_with(Data, classify_send_error(Other))
    end;
handle_pubcomp_in(_, Data) ->
    {ok, Data}.

%%=============================================================%% Inbound Rust frames while connected
%%=============================================================
handle_suback(Meta, #{sock := Sock, sockmod := Mod, subs_pending := Pending,
                      quiet_subs := Quiet} = Data) ->
    case indra_brokerlink:decode_suback_meta(Meta) of
        {ok, #{packet_id := PacketId, codes := Codes}} ->
            case maps:is_key(PacketId, Quiet) of
                true ->
                    %% Re-registration echo: swallow, never re-send.
                    {keep_state, Data#{quiet_subs => maps:remove(PacketId, Quiet)}};
                false ->
                    case maps:is_key(PacketId, Pending) of
                        false ->
                            %% Unsolicited SubAck: ignore.
                            {keep_state, Data};
                        true ->
                            Suback = indra_mqtt_codec:encode_suback(PacketId, Codes),
                            case sock_send(Mod, Sock, Suback) of
                                ok ->
                                    {keep_state, Data#{subs_pending =>
                                                          maps:remove(PacketId, Pending)}};
                                {error, _} ->
                                    stop_with(bump_send_failed(Data), send_failed)
                            end
                    end
            end;
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

%% Maximum PublishOut frames coalesced into one socket write, and the
%% wire-byte cap for the same batch. 64 frames x ~200 B ~= 13 KiB
%% typical, 64 KiB cap for large payloads: one `gen_tcp:send' iolist per
%% mailbox drain instead of one syscall per ~150 B frame. No delayed
%% flush: a lone frame sends immediately. A dedicated sender process per
%% connection was considered and declined: it doubles the process count
%% (500 subscribers -> 1000 processes) and adds a queue to fix a queue,
%% while owner-side batching buys the same syscall reduction with no
%% handover and no new mailbox.
-define(EGRESS_BATCH_MAX_FRAMES, 64).
-define(EGRESS_BATCH_MAX_BYTES, 65536).

%% @private Batch one PublishOut frame with whatever is already queued
%% behind it, then emit in one ordered pass: runs of PublishOut frames
%% go out as a single `gen_tcp:send' iolist (the runtime takes iolists
%% directly, so batching costs no extra copy), control frames flush the
%% run before them so arrival order is exactly preserved. Per-message
%% cost after this change: one ETS `update_counter' at dispatch, one at
%% release, and 1/<=64th of a send syscall per PublishOut frame.
egress_batch(First, Data) ->
    {Queued, Capped} = drain_queued_frames(),
    emit_ordered([First | Queued], Capped, Data).

%% @private Non-blocking drain of queued inbound BrokerLink casts,
%% bounded by frames and body bytes, oldest first. Only
%% `{broker_frame, ...}' casts are removed; any other queued message
%% (core presence, socket signals, timers) stays exactly where it was.
%% The `$gen_cast' tuple shape is gen_statem's stable wire format for
%% casts, relied upon here read-only.
drain_queued_frames() ->
    drain_queued_frames([], 0, 0).

drain_queued_frames(Acc, Frames, Bytes)
  when Frames >= ?EGRESS_BATCH_MAX_FRAMES;
       Bytes >= ?EGRESS_BATCH_MAX_BYTES ->
    {lists:reverse(Acc), true};
drain_queued_frames(Acc, Frames, Bytes) ->
    receive
        {'$gen_cast', {broker_frame, Header, Meta, Payload}} ->
            drain_queued_frames([{Header, Meta, Payload} | Acc],
                                Frames + 1,
                                Bytes + byte_size(Meta) + byte_size(Payload))
    after 0 ->
        {lists:reverse(Acc), false}
    end.

%% @private Emit one ordered drain. When the drain hit its cap, more may
%% be queued: re-trigger through the back of the mailbox (fair to core
%% presence and socket signals; see the `drain_more' handling).
emit_ordered(Frames, Capped, Data) ->
    case emit_frames(Frames, Data, [], 0, 0) of
        {ok, Data1} ->
            case Capped of
                true ->
                    erlang:send_after(0, self(), drain_more),
                    {keep_state, Data1};
                false ->
                    {keep_state, Data1}
            end;
        {stop, _, _} = Stop ->
            Stop
    end.

%% @private Walk one ordered drain: accumulate PublishOut runs, flush
%% before every control frame and at the end, stop on the first failure
%% with everything unsent counted. Returns `{ok, Data}' or the stop.
emit_frames([], Data, Pending, N, B) ->
    case flush_pending(Data, Pending, N, B, []) of
        {ok, Data1} -> {ok, Data1};
        {stop, _, _} = Stop -> Stop
    end;
emit_frames([{Header, Meta, Payload} = _Frame | Rest], Data, Pending, N, B) ->
    case maps:get(opcode, Header, undefined) of
        ?PUBLISH_OUT ->
            case indra_brokerlink:decode_publish_meta(Meta) of
                {ok, #{topic := Topic, packet_id := PacketId, qos := QoS,
                       retain := Retain, dup := Dup, alias := Alias}} ->
                    %% B4-05: the kernel-assigned alias rides the PUBLISH
                    %% alias property toward v5 subscribers (0 means full
                    %% topic, no alias). The meta value is already the
                    %% wire value, framed directly with no round-trip.
                    Packet = indra_mqtt_codec:encode_publish(Topic, PacketId, QoS,
                                                             Retain, Dup, Payload,
                                                             Alias),
                    emit_frames(Rest, Data, [Packet | Pending], N + 1,
                                B + byte_size(Meta) + byte_size(Payload));
                {error, _} ->
                    %% The malformed frame kills the connection, but the
                    %% run ahead of it was already due: deliver it first,
                    %% then close with the dequeued remainder reconciled
                    %% (the flush-failure path reconciles inside
                    %% flush_pending, so count here only on success).
                    case flush_pending(Data, Pending, N, B, Rest) of
                        {ok, Data1} ->
                            count_evaporated(Rest),
                            stop_with(Data1, protocol_error);
                        {stop, _, _} = Stop ->
                            Stop
                    end
            end;
        ?SUBACK_OUT ->
            case flush_pending(Data, Pending, N, B, Rest) of
                {ok, Data1} ->
                    case handle_suback(Meta, Data1) of
                        {keep_state, Data2} ->
                            emit_frames(Rest, Data2, [], 0, 0);
                        {stop, _, _} = Stop ->
                            count_evaporated(Rest),
                            Stop
                    end;
                {stop, _, _} = Stop ->
                    Stop
            end;
        ?PUBACK_OUT ->
            case flush_pending(Data, Pending, N, B, Rest) of
                {ok, Data1} ->
                    case handle_puback_out(Meta, Data1) of
                        {keep_state, Data2} ->
                            emit_frames(Rest, Data2, [], 0, 0);
                        {stop, _, _} = Stop ->
                            count_evaporated(Rest),
                            Stop
                    end;
                {stop, _, _} = Stop ->
                    Stop
            end;
        ?PUBREC_OUT ->
            case flush_pending(Data, Pending, N, B, Rest) of
                {ok, Data1} ->
                    case handle_pubrec_out(Meta, Data1) of
                        {keep_state, Data2} ->
                            emit_frames(Rest, Data2, [], 0, 0);
                        {stop, _, _} = Stop ->
                            count_evaporated(Rest),
                            Stop
                    end;
                {stop, _, _} = Stop ->
                    Stop
            end;
        ?PUBREL_OUT ->
            case flush_pending(Data, Pending, N, B, Rest) of
                {ok, Data1} ->
                    case handle_pubrel_out(Meta, Data1) of
                        {keep_state, Data2} ->
                            emit_frames(Rest, Data2, [], 0, 0);
                        {stop, _, _} = Stop ->
                            count_evaporated(Rest),
                            Stop
                    end;
                {stop, _, _} = Stop ->
                    Stop
            end;
        ?PUBCOMP_OUT ->
            case flush_pending(Data, Pending, N, B, Rest) of
                {ok, Data1} ->
                    case handle_pubcomp_out(Meta, Data1) of
                        {keep_state, Data2} ->
                            emit_frames(Rest, Data2, [], 0, 0);
                        {stop, _, _} = Stop ->
                            count_evaporated(Rest),
                            Stop
                    end;
                {stop, _, _} = Stop ->
                    Stop
            end;
        ?CONN_CLOSE ->
            case flush_pending(Data, Pending, N, B, Rest) of
                {ok, Data1} ->
                    count_evaporated(Rest),
                    stop_with(Data1, kernel_close);
                {stop, _, _} = Stop ->
                    Stop
            end;
        _ ->
            %% Late duplicates or future opcodes: ignore, keep walking.
            emit_frames(Rest, Data, Pending, N, B)
    end.

%% @private Write one accumulated PublishOut run as a single iolist
%% send. Empty runs cost no syscall. On success the credit account is
%% released (which may emit one advisory flow-control frame on the
%% slowed -> healthy transition); on failure the whole unsent run --
%% pending plus the still-unwalked remainder -- is counted and the
%% connection stops with cause `send_failed'.
flush_pending(Data, [], _N, _B, _Rest) ->
    {ok, Data};
flush_pending(Data, Pending, N, B, Rest) ->
    #{sock := Sock, sockmod := Mod} = Data,
    case sock_send(Mod, Sock, lists:reverse(Pending)) of
        ok ->
            {ok, release_credit(Data, N, B)};
        {error, _} ->
            count_evaporated(Rest),
            Unsent = N + count_publish_frames(Rest),
            stop_with(bump_send_failed(Data, Unsent), send_failed)
    end.

%% @private Release a written run against the Q3 credit account. `Bytes'
%% uses the same BrokerLink body measure as dispatch admission, so the
%% two counters cannot drift apart by encoding. A release for a
%% connection with no account (direct test calls without a dispatch
%% pass) is a no-op.
release_credit(Data, 0, 0) ->
    Data;
release_credit(#{conn_id := ConnId} = Data, N, B) ->
    case indra_edge_counters:egress_released(ConnId, N, B) of
        {recovered, UsedF, UsedB} ->
            maybe_send_credit(Data, UsedF, UsedB);
        {ok, _, _} ->
            Data
    end;
release_credit(Data, _N, _B) ->
    Data.

%% @private Emit one advisory flow-control snapshot on the slowed ->
%% healthy transition. Fire-and-forget: the kernel only counts these
%% today, so losing one is harmless; when kernel gating lands a periodic
%% refresh must bound the stall. It must never kill the
%% connection and never advance the sequence on failure.
maybe_send_credit(#{broker := Broker, conn_id := ConnId, seq := Seq} = Data,
                  UsedF, UsedB)
  when is_pid(Broker) ->
    Meta = indra_brokerlink:encode_credit_meta(UsedF, UsedB),
    case catch indra_brokerlink:send(Broker, credit, ConnId, Seq + 1, Meta, <<>>) of
        ok ->
            Data#{seq => Seq + 1};
        _ ->
            Data
    end;
maybe_send_credit(Data, _UsedF, _UsedB) ->
    Data.

%% @private Count PublishOut frames in an unwalked drain remainder
%% (header opcodes only, no decoding: all of them missed the socket).
count_publish_frames(Rest) ->
    lists:foldl(
      fun({Header, _Meta, _Payload}, Acc) ->
          case maps:get(opcode, Header, undefined) of
              ?PUBLISH_OUT -> Acc + 1;
              _ -> Acc
          end
      end, 0, Rest).

%% @private Reconcile a dequeued-but-unwalked drain remainder at a stop:
%% every PublishOut in it evaporates here (never the socket, never the
%% mailbox drain in terminate/3), so label each by QoS now. QoS 2 counts
%% with QoS 1. Best effort on decode: an undecodable remainder is still
%% gone, just unlabelled.
count_evaporated(Rest) ->
    {Qos0, Qos1} = lists:foldl(
      fun({Header, Meta, _Payload}, {A0, A1}) ->
          case maps:get(opcode, Header, undefined) of
              ?PUBLISH_OUT ->
                  case catch indra_brokerlink:decode_publish_meta(Meta) of
                      {ok, #{qos := 0}} -> {A0 + 1, A1};
                      {ok, _} -> {A0, A1 + 1};
                      _ -> {A0, A1}
                  end;
              _ ->
                  {A0, A1}
          end
      end, {0, 0}, Rest),
    catch indra_edge_counters:inc(edge_egress_discarded_at_close_qos0_total, Qos0),
    catch indra_edge_counters:inc(edge_egress_discarded_at_close_qos1_total, Qos1),
    ok.

handle_puback_out(Meta, #{sock := Sock, sockmod := Mod, pubs_pending := Pending} = Data) ->
    case indra_brokerlink:decode_puback_meta(Meta) of
        {ok, #{packet_id := PacketId}} ->
            case maps:is_key(PacketId, Pending) of
                false ->
                    {keep_state, Data};
                true ->
                    case sock_send(Mod, Sock, indra_mqtt_codec:encode_puback(PacketId)) of
                        ok ->
                            {keep_state, Data#{pubs_pending =>
                                                   maps:remove(PacketId, Pending)}};
                        {error, _} ->
                            stop_with(bump_send_failed(Data), send_failed)
                    end
            end;
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

%% @private Forward one kernel PUBREC to the publishing client (D1-01
%% inbound first phase, B4-05 alias rejects carry reason 0x94). The
%% pending entry stays until PUBCOMP so a duplicate PUBLISH still
%% matches; unsolicited PUBRECs are still forwarded (the kernel only
%% sends them for publishes it stored). A nonzero reason code rides the
%% MQTT 5 PUBREC reason field via encode_pubrec/2 so the publisher
%% observes the 0x94 rejection instead of a bare PUBREC.
handle_pubrec_out(Meta, #{sock := Sock, sockmod := Mod} = Data) ->
    case indra_brokerlink:decode_pubrec_meta(Meta) of
        {ok, #{packet_id := PacketId} = Dec} ->
            RC = maps:get(reason_code, Dec, 0),
            case sock_send(Mod, Sock, indra_mqtt_codec:encode_pubrec(PacketId, RC)) of
                ok ->
                    {keep_state, Data};
                {error, _} ->
                    stop_with(bump_send_failed(Data), send_failed)
            end;
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

%% @private Forward one kernel PUBREL to the subscribing client (D1-01
%% outbound second phase).
handle_pubrel_out(Meta, #{sock := Sock, sockmod := Mod} = Data) ->
    case indra_brokerlink:decode_pubrel_meta(Meta) of
        {ok, #{packet_id := PacketId}} ->
            case sock_send(Mod, Sock, indra_mqtt_codec:encode_pubrel(PacketId)) of
                ok ->
                    {keep_state, Data};
                {error, _} ->
                    stop_with(bump_send_failed(Data), send_failed)
            end;
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

%% @private Forward one kernel PUBCOMP to the publishing client (D1-01
%% inbound completion) and release the pending entry.
handle_pubcomp_out(Meta, #{sock := Sock, sockmod := Mod,
                           qos2_pending := Pending} = Data) ->
    case indra_brokerlink:decode_pubcomp_meta(Meta) of
        {ok, #{packet_id := PacketId}} ->
            case sock_send(Mod, Sock, indra_mqtt_codec:encode_pubcomp(PacketId)) of
                ok ->
                    {keep_state, Data#{qos2_pending =>
                                           maps:remove(PacketId, Pending)}};
                {error, _} ->
                    stop_with(bump_send_failed(Data), send_failed)
            end;
        {error, _Reason} ->
            stop_with(Data, protocol_error)
    end.

keepalive_action(#{keepalive := 0}) ->
    %% Keepalive 0 disables the timeout; return a zero-timeout-free action
    %% list entry by cancelling any pending state timeout.
    {state_timeout, infinity, keepalive_timeout};
keepalive_action(#{keepalive := Keepalive}) ->
    {state_timeout, round(Keepalive * 1500), keepalive_timeout}.
