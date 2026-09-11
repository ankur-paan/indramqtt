%% @doc MQTT TCP/TLS listener (BEAM edge side).
%%
%% A supervision-friendly {@code gen_server} that owns the client-facing
%% listen socket (default ports: 1883 plaintext, 8883 TLS) and hands each
%% accepted connection to an {@link indra_conn} process. The blocking
%% accept loop runs in a linked acceptor process so the server itself
%% stays responsive to {@code stop/1} and supervisor signals.
%%
%% TLS termination uses OTP {@code ssl}: with
%% {@code {transport, ssl}, {certfile, Cert}, {keyfile, Key}} the listener
%% accepts via {@code ssl:transport_accept/1} plus a bounded
%% {@code ssl:handshake/2}, then transfers the TLS socket to a conn
%% started with the matching {@code {transport, ssl}} option.
-module(indra_listener).

-behaviour(gen_server).

-export([start_link/0,
         start_link/1,
         stop/1,
         get_port/1]).

%% gen_server callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(DEFAULT_PORT, 1883).
-define(DEFAULT_TLS_PORT, 8883).
-define(HANDSHAKE_TIMEOUT_MS, 5000).

-type listen_opt() :: {port, inet:port_number()}
                    | {transport, tcp | ssl}
                    | {certfile, file:filename()}
                    | {keyfile, file:filename()}
                    | {conn, [tuple()]}.

%%====================================================================
%% API
%%====================================================================

%% @doc Start a plaintext listener on the default MQTT port (1883).
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

%% @doc Start a listener. Options:
%% <ul>
%% <li>{@code {port, Port}} — default 1883 for {@code tcp}, 8883 for
%% {@code ssl}; use 0 for an ephemeral port (see {@link get_port/1}).</li>
%% <li>{@code {transport, tcp | ssl}} — default {@code tcp}.</li>
%% <li>{@code {certfile, Path}, {keyfile, Path}} — required for
%% {@code ssl}; PEM-encoded certificate and private key.</li>
%% <li>{@code {conn, ConnOpts}} — extra options forwarded to every
%% {@code indra_conn} (must include {@code {broker, pid()}}; pass
%% {@code {transport, ssl}} through for TLS sockets).</li>
%% </ul>
-spec start_link([listen_opt()]) -> {ok, pid()} | {error, term()}.
start_link(Opts) when is_list(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

%% @doc Stop the listener (closes the listen socket).
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% @doc Return the actual bound port (useful with {@code {port, 0}}).
-spec get_port(pid()) -> {ok, inet:port_number()} | {error, term()}.
get_port(Pid) ->
    gen_server:call(Pid, get_port).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Opts) ->
    process_flag(trap_exit, true),
    Transport = proplists:get_value(transport, Opts, tcp),
    DefaultPort = case Transport of ssl -> ?DEFAULT_TLS_PORT; _ -> ?DEFAULT_PORT end,
    Port = proplists:get_value(port, Opts, DefaultPort),
    ConnOpts = proplists:get_value(conn, Opts, []),
    SockOpts = [binary, {packet, raw}, {active, false}, {reuseaddr, true}],
    ListenResult = case Transport of
        ssl ->
            %% TLS needs the ssl application (and its tracker sup) even
            %% when embedded without a full release boot.
            {ok, _} = application:ensure_all_started(ssl),
            case {proplists:get_value(certfile, Opts), proplists:get_value(keyfile, Opts)} of
                {undefined, _} -> {error, {missing_option, certfile}};
                {_, undefined} -> {error, {missing_option, keyfile}};
                {Cert, Key} -> ssl:listen(Port, [{certfile, Cert}, {keyfile, Key} | SockOpts])
            end;
        _ ->
            gen_tcp:listen(Port, SockOpts)
    end,
    case ListenResult of
        {ok, LSock} ->
            case bound_port(Transport, LSock) of
                {ok, Actual} ->
                    Acceptor = spawn_link(fun() -> accept_loop(Transport, LSock, ConnOpts) end),
                    {ok, #{transport => Transport, lsock => LSock, port => Actual,
                           acceptor => Acceptor, conn_opts => ConnOpts}};
                {error, Reason} ->
                    catch close_listen(Transport, LSock),
                    {stop, Reason}
            end;
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(get_port, _From, #{port := Port} = State) ->
    {reply, {ok, Port}, State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason}, #{acceptor := Pid} = State) ->
    case Reason of
        normal ->
            %% Listen socket was closed (usually our own shutdown).
            {noreply, State};
        _ ->
            %% Acceptor crashed: re-arm unless the socket is gone.
            #{transport := Transport, lsock := LSock, conn_opts := ConnOpts} = State,
            case listen_alive(Transport, LSock) of
                true ->
                    Acceptor = spawn_link(fun() -> accept_loop(Transport, LSock, ConnOpts) end),
                    {noreply, State#{acceptor => Acceptor}};
                false ->
                    {stop, {acceptor_died, Reason}, State}
            end
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{transport := Transport, lsock := LSock}) ->
    catch close_listen(Transport, LSock),
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Transport helpers
%%====================================================================

bound_port(tcp, LSock) -> inet:port(LSock);
bound_port(ssl, LSock) ->
    case ssl:sockname(LSock) of
        {ok, {_Addr, Port}} -> {ok, Port};
        {error, _} = Err -> Err
    end.

listen_alive(tcp, LSock) ->
    case inet:getstat(LSock) of
        {ok, _} -> true;
        _ -> false
    end;
listen_alive(ssl, LSock) ->
    case ssl:getstat(LSock) of
        {ok, _} -> true;
        _ -> false
    end.

close_listen(tcp, LSock) -> gen_tcp:close(LSock);
close_listen(ssl, LSock) -> ssl:close(LSock).

%%====================================================================
%% Acceptor loop (linked helper process)
%%====================================================================

%% @private Block in accept; each success (plus TLS handshake) spawns a
%% conn and transfers socket ownership before arming it. Ends when the
%% listen socket closes.
accept_loop(Transport, LSock, ConnOpts) ->
    case accept_one(Transport, LSock) of
        {ok, Sock} ->
            case indra_conn:start_link(Sock, ConnOpts) of
                {ok, Pid} ->
                    case controlling_process(Transport, Sock, Pid) of
                        ok ->
                            gen_statem:cast(Pid, takeover);
                        {error, _} ->
                            catch close_socket(Transport, Sock),
                            catch indra_conn:stop(Pid)
                    end;
                {error, _} ->
                    catch close_socket(Transport, Sock)
            end,
            accept_loop(Transport, LSock, ConnOpts);
        {error, closed} ->
            exit(normal);
        {error, _Reason} ->
            %% Transient accept failure: back off briefly, then retry.
            timer:sleep(100),
            accept_loop(Transport, LSock, ConnOpts)
    end.

accept_one(tcp, LSock) ->
    gen_tcp:accept(LSock);
accept_one(ssl, LSock) ->
    case ssl:transport_accept(LSock) of
        {ok, Sock} ->
            case ssl:handshake(Sock, ?HANDSHAKE_TIMEOUT_MS) of
                {ok, TLSSock} -> {ok, TLSSock};
                {error, _} = Err ->
                    catch ssl:close(Sock),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

controlling_process(tcp, Sock, Pid) -> gen_tcp:controlling_process(Sock, Pid);
controlling_process(ssl, Sock, Pid) -> ssl:controlling_process(Sock, Pid).

close_socket(tcp, Sock) -> gen_tcp:close(Sock);
close_socket(ssl, Sock) -> ssl:close(Sock).
