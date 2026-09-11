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
%% with PUBACK), PINGREQ is answered on the edge, DISCONNECT unbinds and
%% closes. Inbound Rust frames (PublishOut, PubAckOut, SubAckOut) are
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
%% {@code {broker_down}} casts (broadcast by the brokerlink client).
%%
%% Broker protocol (also implemented by test mocks): the broker is any
%% process answering {@code gen_server:call(Broker, {send, Opcode,
%% ConnId, SeqNo, Meta, Payload}, Timeout)}. Inbound Rust frames arrive
%% via {@link broker_frame/4}.
-module(indra_conn).

-behaviour(gen_statem).

-export([start_link/2,
         stop/1,
         broker_frame/4]).

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
-define(PUBACK_OUT, 16#0023).
-define(SUBSCRIBE_IN, 16#0030).
-define(SUBACK_OUT, 16#0031).
-define(DEFAULT_CONNECT_TIMEOUT_MS, 10000).
%% Max client bytes buffered while the core is down; beyond this the
%% connection fails closed instead of ballooning the edge.
-define(MAX_HOLD_BUFFER_BYTES, 1048576).

-type conn_opt() :: {broker, pid()}
                  | {conn_id, non_neg_integer()}
                  | {connect_timeout_ms, pos_integer()}
                  | {transport, tcp | ssl}.

%%====================================================================
%% API
%%====================================================================

%% @doc Start a connection process for an accepted socket.
%%
%% The socket must be in passive mode and owned by the caller; ownership
%% is transferred here on {@code takeover}. Options:
%% <ul>
%% <li>{@code {broker, pid()}} — required BrokerLink client (or mock).</li>
%% <li>{@code {conn_id, N}} — BrokerLink connection id; defaults to a
%% fresh positive unique integer.</li>
%% <li>{@code {connect_timeout_ms, Ms}} — first-packet deadline,
%% default 10000.</li>
%% <li>{@code {transport, tcp | ssl}} — socket driver; default
%% {@code tcp}. Must match how the socket was accepted.</li>
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

%%====================================================================
%% gen_statem callbacks
%%====================================================================

callback_mode() ->
    handle_event_function.

init({Sock, Opts}) ->
    case proplists:get_value(broker, Opts) of
        undefined ->
            {stop, {missing_option, broker}};
        Broker when is_pid(Broker) ->
            ConnId = proplists:get_value(conn_id, Opts,
                                         erlang:unique_integer([positive, monotonic])),
            Timeout = proplists:get_value(connect_timeout_ms, Opts,
                                          ?DEFAULT_CONNECT_TIMEOUT_MS),
            Transport = proplists:get_value(transport, Opts, tcp),
            SockMod = case Transport of ssl -> ssl; _ -> gen_tcp end,
            Data = #{sock => Sock,
                     sockmod => SockMod,
                     broker => Broker,
                     conn_id => ConnId,
                     connect_timeout_ms => Timeout,
                     buffer => <<>>,
                     seq => 0,
                     pending => undefined,
                     client_id => undefined,
                     keepalive => 0,
                     session_id => undefined,
                     subs_pending => #{},
                     pubs_pending => #{},
                     subs => #{},
                     quiet_subs => #{},
                     rebinding => false},
            {ok, await_connect, Data}
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
            {stop, normal, Data}
    end;

%% --- core presence ----------------------------------------------------
%% Await-connect has no session to hold: adopt a new broker pid so the
%% pending handshake (if any) can be re-driven on arrival.
handle_event(cast, {broker_up, NewBroker}, await_connect, #{broker := Broker} = Data)
  when NewBroker =/= Broker ->
    Data1 = Data#{broker => NewBroker},
    case maps:get(pending, Data1, undefined) of
        undefined ->
            {keep_state, Data1};
        _ ->
            resend_bind(Data1)
    end;
handle_event(cast, {broker_up, _Same}, await_connect, Data) ->
    {keep_state, Data};
handle_event(cast, {broker_down}, await_connect, Data) ->
    {keep_state, Data};
%% Connected with a fresh broker identity (restart): hold and rebind.
handle_event(cast, {broker_up, NewBroker}, connected, #{broker := Broker} = Data)
  when NewBroker =/= Broker ->
    start_rebind(Data#{broker => NewBroker});
handle_event(cast, {broker_up, _Same}, connected, Data) ->
    {keep_state, Data};
handle_event(cast, {broker_down}, connected, Data) ->
    {next_state, await_core, Data};
%% Already holding: adopt + rebind unless a rebind is already in flight.
handle_event(cast, {broker_up, NewBroker}, await_core, Data) ->
    case maps:get(rebinding, Data, false) of
        true ->
            {keep_state, Data#{broker => NewBroker}};
        false ->
            start_rebind(Data#{broker => NewBroker})
    end;
handle_event(cast, {broker_down}, await_core, Data) ->
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
            handle_publish_out(Meta, Payload, Data);
        ?PUBACK_OUT ->
            handle_puback_out(Meta, Data);
        _ ->
            %% Late duplicates or future opcodes: ignore for now.
            {keep_state, Data}
    end;
handle_event(cast, {broker_frame, Header, Meta, _Payload}, await_core, Data) ->
    case maps:get(opcode, Header, undefined) of
        ?SESSION_BINDING ->
            handle_rebind_binding(Meta, Data);
        _ ->
            %% Stale pre-crash frames: ignore while holding.
            {keep_state, Data}
    end;

%% --- socket transport normalization (ssl driver support) --------------
handle_event(info, {ssl, Sock, Bytes}, State, #{sock := Sock} = Data) ->
    handle_event(info, {tcp, Sock, Bytes}, State, Data);
handle_event(info, {ssl_closed, Sock}, State, #{sock := Sock} = Data) ->
    handle_event(info, {tcp_closed, Sock}, State, Data);
handle_event(info, {ssl_error, Sock, Reason}, State, #{sock := Sock} = Data) ->
    handle_event(info, {tcp_error, Sock, Reason}, State, Data);

%% --- client TCP bytes while awaiting CONNECT --------------------------
handle_event(info, {tcp, Sock, Bytes}, await_connect, #{sock := Sock} = Data) ->
    arm_socket(Data),
    Buf = <<(maps:get(buffer, Data))/binary, Bytes/binary>>,
    handle_connect_bytes(Buf, Data#{buffer => <<>>});
handle_event(info, {tcp_closed, Sock}, _State, #{sock := Sock} = Data) ->
    {stop, normal, Data};
handle_event(info, {tcp_error, Sock, _Reason}, _State, #{sock := Sock} = Data) ->
    {stop, normal, Data};

%% --- client TCP bytes while connected: the messaging loop -------------
handle_event(info, {tcp, Sock, Bytes}, connected, #{sock := Sock} = Data) ->
    arm_socket(Data),
    Buf = <<(maps:get(buffer, Data))/binary, Bytes/binary>>,
    handle_connected_bytes(Buf, Data#{buffer => <<>>});
handle_event(info, {tcp_closed, Sock}, connected, #{sock := Sock} = Data) ->
    {stop, normal, Data};
handle_event(info, {tcp_error, Sock, _Reason}, connected, #{sock := Sock} = Data) ->
    {stop, normal, Data};

%% --- client TCP bytes while holding for the core -----------------------
handle_event(info, {tcp, Sock, Bytes}, await_core, #{sock := Sock} = Data) ->
    arm_socket(Data),
    Buf = <<(maps:get(buffer, Data))/binary, Bytes/binary>>,
    case byte_size(Buf) > ?MAX_HOLD_BUFFER_BYTES of
        true ->
            %% Flood during outage: fail closed, do not balloon.
            {stop, normal, Data};
        false ->
            hold_bytes(Buf, Data#{buffer => <<>>})
    end;
handle_event(info, {tcp_closed, Sock}, await_core, #{sock := Sock} = Data) ->
    {stop, normal, Data};
handle_event(info, {tcp_error, Sock, _Reason}, await_core, #{sock := Sock} = Data) ->
    {stop, normal, Data};

%% --- buffered bytes pipelined behind CONNECT ---------------------------
handle_event(internal, drain_buffer, connected, Data) ->
    handle_connected_bytes(maps:get(buffer, Data), Data#{buffer => <<>>});

%% --- timers -------------------------------------------------------------
handle_event(state_timeout, connect_timeout, await_connect, Data) ->
    %% Peer never sent CONNECT: do not leak the socket.
    {stop, normal, Data};
handle_event(state_timeout, keepalive_timeout, connected, Data) ->
    %% Peer exceeded 1.5 x keepalive without any packet.
    {stop, normal, Data};

%% --- fallback -------------------------------------------------------------
handle_event(_Type, _Event, _State, Data) ->
    {keep_state, Data}.

terminate(_Reason, _State, #{sock := Sock, sockmod := Mod, conn_id := ConnId}) ->
    catch indra_conn_registry:unregister(ConnId),
    catch sock_close(Mod, Sock),
    ok;
terminate(_Reason, _State, _Data) ->
    ok.

%%====================================================================
%% Socket driver helpers (tcp | ssl)
%%====================================================================

sock_send(gen_tcp, Sock, Bin) -> gen_tcp:send(Sock, Bin);
sock_send(ssl, Sock, Bin) -> ssl:send(Sock, Bin).

sock_setopts(gen_tcp, Sock) -> inet:setopts(Sock, [{active, once}]);
sock_setopts(ssl, Sock) -> ssl:setopts(Sock, [{active, once}]).

sock_close(gen_tcp, Sock) -> gen_tcp:close(Sock);
sock_close(ssl, Sock) -> ssl:close(Sock).

arm_socket(#{sock := Sock, sockmod := Mod}) ->
    catch sock_setopts(Mod, Sock),
    ok.

%%====================================================================
%% Handshake helpers
%%====================================================================

handle_connect_bytes(Buf, Data) ->
    case indra_mqtt_codec:decode_packet(Buf) of
        {ok, #{type := 1, payload := Payload}, Rest} ->
            handle_connect_packet(Payload, Rest, Data);
        {ok, #{type := _Other}, _Rest} ->
            %% MQTT 3.1.1 §3.1: first packet MUST be CONNECT.
            {stop, normal, Data};
        {more, _Need} ->
            {keep_state, Data#{buffer => Buf}};
        {error, _Reason} ->
            {stop, normal, Data}
    end.

handle_connect_packet(Payload, Rest, #{broker := Broker, conn_id := ConnId, seq := Seq} = Data) ->
    case indra_mqtt_codec:decode_connect(Payload) of
        {ok, #{client_id := ClientId, clean_start := CleanStart, keepalive := Keepalive,
               username := User, password := Pass}} ->
            Meta = indra_brokerlink:encode_bind_meta(ClientId, CleanStart, Keepalive,
                                                     {User, Pass}),
            case catch indra_brokerlink:send(Broker, ?BIND_CONNECTION, ConnId, Seq + 1, Meta, <<>>) of
                ok ->
                    Pending = #{client_id => ClientId, keepalive => Keepalive},
                    %% Stash bytes pipelined behind CONNECT; they drain once
                    %% the handshake completes (see `drain_buffer`).
                    {keep_state, Data#{seq => Seq + 1,
                                       pending => Pending,
                                       buffer => Rest}};
                _ ->
                    {stop, normal, Data}
            end;
        {error, _Reason} ->
            {stop, normal, Data}
    end.

%% @private Re-send the pending bind to a replacement broker (core flap
%% mid-handshake). Drops back to waiting on failure.
resend_bind(#{broker := Broker, conn_id := ConnId, seq := Seq,
              pending := #{client_id := ClientId, keepalive := Keepalive}} = Data) ->
    Meta = indra_brokerlink:encode_bind_meta(ClientId, false, Keepalive,
                                             {undefined, undefined}),
    case catch indra_brokerlink:send(Broker, ?BIND_CONNECTION, ConnId, Seq + 1, Meta, <<>>) of
        ok ->
            {keep_state, Data#{seq => Seq + 1}};
        _ ->
            {keep_state, Data}
    end;
resend_bind(Data) ->
    {keep_state, Data}.

handle_session_binding(Meta, #{sock := Sock, sockmod := Mod} = Data) ->
    case indra_brokerlink:decode_session_binding_meta(Meta) of
        {ok, #{session_id := SessionId,
               session_present := Present,
               return_code := RC}} ->
            Connack = indra_mqtt_codec:encode_connack(Present, RC),
            case sock_send(Mod, Sock, Connack) of
                ok when RC =:= 0 ->
                    Pending = maps:get(pending, Data, #{client_id => <<>>,
                                                        keepalive => 0}),
                    Data1 = Data#{session_id => SessionId,
                                  client_id => maps:get(client_id, Pending, <<>>),
                                  keepalive => maps:get(keepalive, Pending, 0)},
                    {next_state, connected, Data1,
                     [keepalive_action(Data1), {next_event, internal, drain_buffer}]};
                _ ->
                    %% Rejected (RC /= 0) or send failed: CONNACK already
                    %% flushed on success paths; just close.
                    {stop, normal, Data}
            end;
        {error, _Reason} ->
            {stop, normal, Data}
    end.

%%====================================================================
%% Core holding + rebind (Sprint 11 restart immunity)
%%====================================================================

%% @private Begin recovery: re-bind the session, always non-clean so a
%% surviving core resumes (present=true, offline replay follows) while a
%% fresh core simply recreates. Core-side tracking resets; the client
%% buffer is preserved for the post-rebind drain.
start_rebind(#{broker := Broker, conn_id := ConnId, seq := Seq,
               client_id := ClientId, keepalive := Keepalive} = Data)
  when is_binary(ClientId) ->
    Meta = indra_brokerlink:encode_bind_meta(ClientId, false, Keepalive,
                                             {undefined, undefined}),
    case catch indra_brokerlink:send(Broker, ?BIND_CONNECTION, ConnId, Seq + 1, Meta, <<>>) of
        ok ->
            {next_state, await_core, Data#{seq => Seq + 1,
                                           subs_pending => #{},
                                           pubs_pending => #{},
                                           quiet_subs => #{},
                                           rebinding => true}};
        _ ->
            %% Replacement core already gone: hold for the next sweep.
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
            {stop, normal, Data}
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
                {error, _} -> {stop, normal, Data}
            end;
        {ok, _Other, Rest} ->
            %% Stash this packet's bytes, keep scanning for pings.
            Used = byte_size(Buf) - byte_size(Rest),
            <<This:Used/binary, _/binary>> = Buf,
            hold_scan(Rest, Data, <<Held/binary, This/binary>>);
        {more, _Need} ->
            {keep_state, Data#{buffer => <<Held/binary, Buf/binary>>}};
        {error, _Reason} ->
            {stop, normal, Data}
    end.

%%====================================================================
%% Connected messaging loop
%%====================================================================

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
            {stop, normal, Data}
    end.

%% @private Handle one decoded client packet. Returns `{ok, Data}` to
%% continue or `{stop, normal, Data}` to close the connection.
handle_mqtt_packet(#{type := 8, payload := Payload}, Data) ->
    handle_subscribe_packet(Payload, Data);
handle_mqtt_packet(#{type := 3, flags := Flags, payload := Payload}, Data) ->
    handle_publish_packet(Payload, Flags, Data);
handle_mqtt_packet(#{type := 12}, #{sock := Sock, sockmod := Mod} = Data) ->
    %% Fast edge PINGRESP; any packet resets keepalive via the caller.
    case sock_send(Mod, Sock, <<16#D0, 16#00>>) of
        ok -> {ok, Data};
        {error, _} -> {stop, normal, Data}
    end;
handle_mqtt_packet(#{type := 14}, Data) ->
    handle_disconnect(Data);
handle_mqtt_packet(#{type := 4}, Data) ->
    %% Inbound PUBACK for our QoS 1 downstream deliveries: accepted and
    %% ignored until per-subscriber inflight tracking lands.
    {ok, Data};
handle_mqtt_packet(_Other, Data) ->
    %% CONNECT repeats, CONNACK/SUBACK from a client, UNSUBSCRIBE and any
    %% other unexpected packet: protocol violation, close.
    {stop, normal, Data}.

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
                _ ->
                    {stop, normal, Data}
            end;
        {error, _Reason} ->
            {stop, normal, Data}
    end.

handle_publish_packet(Payload, Flags, Data) ->
    case indra_mqtt_codec:decode_publish(Payload, Flags) of
        {ok, #{topic := Topic, packet_id := PacketId, qos := QoS,
               retain := Retain, dup := Dup, payload := AppPayload}} ->
            #{broker := Broker, conn_id := ConnId, seq := Seq,
              pubs_pending := Pending} = Data,
            Meta = indra_brokerlink:encode_publish_meta(Topic, PacketId, QoS, Retain, Dup),
            case catch indra_brokerlink:send(Broker, ?PUBLISH_IN, ConnId, Seq + 1, Meta, AppPayload) of
                ok when QoS =:= 1 ->
                    {ok, Data#{seq => Seq + 1,
                               pubs_pending => Pending#{PacketId => true}}};
                ok ->
                    {ok, Data#{seq => Seq + 1}};
                _ ->
                    {stop, normal, Data}
            end;
        {error, _Reason} ->
            {stop, normal, Data}
    end.

handle_disconnect(#{broker := Broker, conn_id := ConnId, seq := Seq,
                    client_id := ClientId} = Data) ->
    %% Fire-and-forget unbind: the socket closes regardless.
    Meta = indra_brokerlink:encode_unbind_meta(ClientId),
    catch indra_brokerlink:send(Broker, ?UNBIND_CONNECTION, ConnId, Seq + 1, Meta, <<>>),
    {stop, normal, Data}.

%%====================================================================
%% Inbound Rust frames while connected
%%====================================================================

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
                                    {stop, normal, Data}
                            end
                    end
            end;
        {error, _Reason} ->
            {stop, normal, Data}
    end.

handle_publish_out(Meta, AppPayload, #{sock := Sock, sockmod := Mod} = Data) ->
    case indra_brokerlink:decode_publish_meta(Meta) of
        {ok, #{topic := Topic, packet_id := PacketId, qos := QoS,
               retain := Retain, dup := Dup}} ->
            Packet = indra_mqtt_codec:encode_publish(Topic, PacketId, QoS,
                                                     Retain, Dup, AppPayload),
            case sock_send(Mod, Sock, Packet) of
                ok -> {keep_state, Data};
                {error, _} -> {stop, normal, Data}
            end;
        {error, _Reason} ->
            {stop, normal, Data}
    end.

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
                            {stop, normal, Data}
                    end
            end;
        {error, _Reason} ->
            {stop, normal, Data}
    end.

keepalive_action(#{keepalive := 0}) ->
    %% Keepalive 0 disables the timeout; return a zero-timeout-free action
    %% list entry by cancelling any pending state timeout.
    {state_timeout, infinity, keepalive_timeout};
keepalive_action(#{keepalive := Keepalive}) ->
    {state_timeout, round(Keepalive * 1500), keepalive_timeout}.
