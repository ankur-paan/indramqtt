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
%% <li>{@code connected}: relays nothing yet (later sprints); supervises
%% the MQTT keepalive (1.5 x keepalive seconds) and closes idle peers.</li>
%% </ul>
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
                     keepalive => 0,
                     session_id => undefined},
            {ok, await_connect, Data}
    end.

%% --- takeover: claim a transferred socket and arm it -----------------
handle_event(cast, takeover, await_connect,
             #{sock := Sock, connect_timeout_ms := Timeout} = Data) ->
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
handle_event(cast, {broker_frame, _Header, _Meta, _Payload}, connected, Data) ->
    %% Later sprints route PublishOut/SubAck here; ignore for now.
    {keep_state, Data};

%% --- client TCP bytes while awaiting CONNECT --------------------------
handle_event(info, {tcp, Sock, Bytes}, await_connect, #{sock := Sock} = Data) ->
    arm_socket(Sock),
    Buf = <<(maps:get(buffer, Data))/binary, Bytes/binary>>,
    handle_connect_bytes(Buf, Data#{buffer => <<>>});
handle_event(info, {tcp_closed, Sock}, _State, #{sock := Sock} = Data) ->
    {stop, normal, Data};
handle_event(info, {tcp_error, Sock, _Reason}, _State, #{sock := Sock} = Data) ->
    {stop, normal, Data};

%% --- client TCP bytes while connected (keepalive supervision only) ----
handle_event(info, {tcp, Sock, _Bytes}, connected, #{sock := Sock} = Data) ->
    arm_socket(Sock),
    {keep_state, Data, [keepalive_action(Data)]};
handle_event(info, {tcp_closed, Sock}, connected, #{sock := Sock} = Data) ->
    {stop, normal, Data};
handle_event(info, {tcp_error, Sock, _Reason}, connected, #{sock := Sock} = Data) ->
    {stop, normal, Data};

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

terminate(_Reason, _State, #{sock := Sock}) ->
    catch gen_tcp:close(Sock),
    ok;
terminate(_Reason, _State, _Data) ->
    ok.

%%====================================================================
%% Handshake helpers
%%====================================================================

handle_connect_bytes(Buf, Data) ->
    case indra_mqtt_codec:decode_packet(Buf) of
        {ok, #{type := 1, payload := Payload}, _Rest} ->
            handle_connect_packet(Payload, Data);
        {ok, #{type := _Other}, _Rest} ->
            %% MQTT 3.1.1 §3.1: first packet MUST be CONNECT.
            {stop, normal, Data};
        {more, _Need} ->
            {keep_state, Data#{buffer => Buf}};
        {error, _Reason} ->
            {stop, normal, Data}
    end.

handle_connect_packet(Payload, #{broker := Broker, conn_id := ConnId, seq := Seq} = Data) ->
    case indra_mqtt_codec:decode_connect(Payload) of
        {ok, #{client_id := ClientId, clean_start := CleanStart, keepalive := Keepalive}} ->
            Meta = indra_brokerlink:encode_bind_meta(ClientId, CleanStart, Keepalive),
            case catch indra_brokerlink:send(Broker, ?BIND_CONNECTION, ConnId, Seq + 1, Meta, <<>>) of
                ok ->
                    Pending = #{client_id => ClientId, keepalive => Keepalive},
                    {keep_state, Data#{seq => Seq + 1, pending => Pending}};
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
                    Keepalive = maps:get(keepalive, maps:get(pending, Data, #{keepalive => 0}),
                                         0),
                    {next_state, connected,
                     Data#{session_id => SessionId, keepalive => Keepalive},
                     [keepalive_action(Data#{keepalive => Keepalive})]};
                _ ->
                    %% Rejected (RC /= 0) or send failed: CONNACK already
                    %% flushed on success paths; just close.
                    {stop, normal, Data}
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
