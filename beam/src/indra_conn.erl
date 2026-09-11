%% @doc One MQTT client connection (BEAM edge side).
%%
%% Connection != Session: this process owns a single client TCP socket
%% (framing, keepalive supervision) and borrows session truth from the
%% Rust core over BrokerLink. It never stores subscriptions or retained
%% messages itself.
%%
%% State machine: {@code await_connect -> connected}.
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
%% </ul>
%%
%% Inbound Rust frames normally arrive via {@code indra_brokerlink},
%% which routes them through {@code indra_conn_registry}; {@link
%% broker_frame/4} is the same entry point for tests and direct callers.
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

-type conn_opt() :: {broker, pid()}
                  | {conn_id, non_neg_integer()}
                  | {connect_timeout_ms, pos_integer()}.

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
            Data = #{sock => Sock,
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
                     pubs_pending => #{}},
            {ok, await_connect, Data}
    end.

%% --- takeover: claim a transferred socket and arm it -----------------
handle_event(cast, takeover, await_connect,
             #{sock := Sock, conn_id := ConnId, connect_timeout_ms := Timeout} = Data) ->
    ok = indra_conn_registry:register(ConnId, self()),
    case inet:setopts(Sock, [{active, once}]) of
        ok ->
            {keep_state, Data, [{state_timeout, Timeout, connect_timeout}]};
        {error, _} ->
            {stop, normal, Data}
    end;

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

%% --- client TCP bytes while awaiting CONNECT --------------------------
handle_event(info, {tcp, Sock, Bytes}, await_connect, #{sock := Sock} = Data) ->
    arm_socket(Sock),
    Buf = <<(maps:get(buffer, Data))/binary, Bytes/binary>>,
    handle_connect_bytes(Buf, Data#{buffer => <<>>});
handle_event(info, {tcp_closed, Sock}, _State, #{sock := Sock} = Data) ->
    {stop, normal, Data};
handle_event(info, {tcp_error, Sock, _Reason}, _State, #{sock := Sock} = Data) ->
    {stop, normal, Data};

%% --- client TCP bytes while connected: the messaging loop -------------
handle_event(info, {tcp, Sock, Bytes}, connected, #{sock := Sock} = Data) ->
    arm_socket(Sock),
    Buf = <<(maps:get(buffer, Data))/binary, Bytes/binary>>,
    handle_connected_bytes(Buf, Data#{buffer => <<>>});
handle_event(info, {tcp_closed, Sock}, connected, #{sock := Sock} = Data) ->
    {stop, normal, Data};
handle_event(info, {tcp_error, Sock, _Reason}, connected, #{sock := Sock} = Data) ->
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

terminate(_Reason, _State, #{sock := Sock, conn_id := ConnId}) ->
    catch indra_conn_registry:unregister(ConnId),
    catch gen_tcp:close(Sock),
    ok;
terminate(_Reason, _State, _Data) ->
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
        {ok, #{client_id := ClientId, clean_start := CleanStart, keepalive := Keepalive}} ->
            Meta = indra_brokerlink:encode_bind_meta(ClientId, CleanStart, Keepalive),
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

handle_session_binding(Meta, #{sock := Sock} = Data) ->
    case indra_brokerlink:decode_session_binding_meta(Meta) of
        {ok, #{session_id := SessionId,
               session_present := Present,
               return_code := RC}} ->
            Connack = indra_mqtt_codec:encode_connack(Present, RC),
            case gen_tcp:send(Sock, Connack) of
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
handle_mqtt_packet(#{type := 12}, #{sock := Sock} = Data) ->
    %% Fast edge PINGRESP; any packet resets keepalive via the caller.
    case gen_tcp:send(Sock, <<16#D0, 16#00>>) of
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
              client_id := ClientId, subs_pending := Pending} = Data,
            Meta = indra_brokerlink:encode_subscribe_meta(PacketId, ClientId, Subs),
            case catch indra_brokerlink:send(Broker, ?SUBSCRIBE_IN, ConnId, Seq + 1, Meta, <<>>) of
                ok ->
                    {ok, Data#{seq => Seq + 1,
                               subs_pending => Pending#{PacketId => true}}};
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

handle_suback(Meta, #{sock := Sock, subs_pending := Pending} = Data) ->
    case indra_brokerlink:decode_suback_meta(Meta) of
        {ok, #{packet_id := PacketId, codes := Codes}} ->
            case maps:is_key(PacketId, Pending) of
                false ->
                    %% Unsolicited SubAck: ignore.
                    {keep_state, Data};
                true ->
                    Suback = indra_mqtt_codec:encode_suback(PacketId, Codes),
                    case gen_tcp:send(Sock, Suback) of
                        ok ->
                            {keep_state, Data#{subs_pending => maps:remove(PacketId, Pending)}};
                        {error, _} ->
                            {stop, normal, Data}
                    end
            end;
        {error, _Reason} ->
            {stop, normal, Data}
    end.

handle_publish_out(Meta, AppPayload, #{sock := Sock} = Data) ->
    case indra_brokerlink:decode_publish_meta(Meta) of
        {ok, #{topic := Topic, packet_id := PacketId, qos := QoS,
               retain := Retain, dup := Dup}} ->
            Packet = indra_mqtt_codec:encode_publish(Topic, PacketId, QoS,
                                                     Retain, Dup, AppPayload),
            case gen_tcp:send(Sock, Packet) of
                ok -> {keep_state, Data};
                {error, _} -> {stop, normal, Data}
            end;
        {error, _Reason} ->
            {stop, normal, Data}
    end.

handle_puback_out(Meta, #{sock := Sock, pubs_pending := Pending} = Data) ->
    case indra_brokerlink:decode_puback_meta(Meta) of
        {ok, #{packet_id := PacketId}} ->
            case maps:is_key(PacketId, Pending) of
                false ->
                    {keep_state, Data};
                true ->
                    case gen_tcp:send(Sock, indra_mqtt_codec:encode_puback(PacketId)) of
                        ok ->
                            {keep_state, Data#{pubs_pending => maps:remove(PacketId, Pending)}};
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

arm_socket(Sock) ->
    catch inet:setopts(Sock, [{active, once}]),
    ok.
