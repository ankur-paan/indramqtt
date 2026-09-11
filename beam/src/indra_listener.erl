%% @doc MQTT TCP listener (BEAM edge side).
%%
%% A supervision-friendly {@code gen_server} that owns the client-facing
%% listen socket (default port 1883) and hands each accepted connection
%% to an {@link indra_conn} process. The blocking {@code gen_tcp:accept}
%% loop runs in a linked acceptor process so the server itself stays
%% responsive to {@code stop/1} and supervisor signals.
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

-type listen_opt() :: {port, inet:port_number()}
                    | {conn, [tuple()]}.

%%====================================================================
%% API
%%====================================================================

%% @doc Start a listener on the default MQTT port (1883).
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

%% @doc Start a listener. Options:
%% <ul>
%% <li>{@code {port, Port}} — default 1883; use 0 for an ephemeral port
%% (see {@link get_port/1}).</li>
%% <li>{@code {conn, ConnOpts}} — extra options forwarded to every
%% {@code indra_conn} (must include {@code {broker, pid()}}).</li>
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
    Port = proplists:get_value(port, Opts, ?DEFAULT_PORT),
    ConnOpts = proplists:get_value(conn, Opts, []),
    case gen_tcp:listen(Port, [binary, {packet, raw},
                               {active, false}, {reuseaddr, true}]) of
        {ok, LSock} ->
            Acceptor = spawn_link(fun() -> accept_loop(LSock, ConnOpts) end),
            {ok, #{lsock => LSock, acceptor => Acceptor, conn_opts => ConnOpts}};
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(get_port, _From, #{lsock := LSock} = State) ->
    {reply, inet:port(LSock), State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason}, #{acceptor := Pid, lsock := LSock} = State) ->
    case Reason of
        normal ->
            %% Listen socket was closed (usually our own shutdown).
            {noreply, State};
        _ ->
            %% Acceptor crashed: re-arm unless the socket is gone.
            case inet:getstat(LSock) of
                {ok, _} ->
                    ConnOpts = maps:get(conn_opts, State),
                    Acceptor = spawn_link(fun() -> accept_loop(LSock, ConnOpts) end),
                    {noreply, State#{acceptor => Acceptor}};
                {error, _} ->
                    {stop, {acceptor_died, Reason}, State}
            end
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{lsock := LSock}) ->
    catch gen_tcp:close(LSock),
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Acceptor loop (linked helper process)
%%====================================================================

%% @private Block in accept; each success spawns a conn and transfers
%% socket ownership before arming it. Ends when the listen socket closes.
accept_loop(LSock, ConnOpts) ->
    case gen_tcp:accept(LSock) of
        {ok, Sock} ->
            case indra_conn:start_link(Sock, ConnOpts) of
                {ok, Pid} ->
                    case gen_tcp:controlling_process(Sock, Pid) of
                        ok ->
                            gen_statem:cast(Pid, takeover);
                        {error, _} ->
                            catch gen_tcp:close(Sock),
                            catch indra_conn:stop(Pid)
                    end;
                {error, _} ->
                    catch gen_tcp:close(Sock)
            end,
            accept_loop(LSock, ConnOpts);
        {error, closed} ->
            exit(normal);
        {error, _Reason} ->
            %% Transient accept failure: back off briefly, then retry.
            timer:sleep(100),
            accept_loop(LSock, ConnOpts)
    end.
