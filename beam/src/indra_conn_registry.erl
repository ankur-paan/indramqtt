%% @doc IndraMQTT Edge connection registry: ConnId -> connection pid.
%%
%% An ETS-backed directory letting the BrokerLink IPC client route
%% inbound Rust frames (PublishOut, PubAckOut, SubAckOut, SessionBinding)
%% to the owning {@code indra_conn} process. Lookups hit ETS directly
%% (concurrent, no server round-trip); registration goes through the
%% supervised server process so liveness monitors are owned by the
%% registry itself and dead connections are always reaped. All API
%% functions are total: they degrade gracefully when the server is
%% absent (e.g. standalone clients in tests).
-module(indra_conn_registry).

-behaviour(gen_server).

-export([start_link/0,
         stop/1,
         register/2,
         unregister/1,
         lookup/1,
         members/0,
         notify_all/1]).

%% gen_server callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(TABLE, indra_conn_registry).

%%====================================================================
%% API
%%====================================================================

%% @doc Start the registry (owns the named ETS table).
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Stop the registry (deletes the ETS table).
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% @doc Map ConnId to Pid (overwrites any previous entry).
-spec register(non_neg_integer(), pid()) -> ok.
register(ConnId, Pid) when is_integer(ConnId), ConnId >= 0, is_pid(Pid) ->
    case whereis(?MODULE) of
        undefined ->
            ok;
        Server ->
            gen_server:call(Server, {register, ConnId, Pid})
    end.

%% @doc Remove the ConnId mapping, if present.
-spec unregister(non_neg_integer()) -> ok.
unregister(ConnId) when is_integer(ConnId), ConnId >= 0 ->
    case whereis(?MODULE) of
        undefined ->
            ok;
        Server ->
            gen_server:call(Server, {unregister, ConnId})
    end.

%% @doc Find the live owner of ConnId.
-spec lookup(non_neg_integer()) -> {ok, pid()} | {error, not_found}.
lookup(ConnId) when is_integer(ConnId), ConnId >= 0 ->
    case ets:whereis(?TABLE) of
        undefined ->
            {error, not_found};
        _ ->
            case ets:lookup(?TABLE, ConnId) of
                [{ConnId, _MRef, Pid}] -> {ok, Pid};
                [] -> {error, not_found}
            end
    end.

%% @doc List every registered `{ConnId, Pid}` pair (e.g. for rebind
%% sweeps). Empty when the registry is absent.
-spec members() -> [{non_neg_integer(), pid()}].
members() ->
    case ets:whereis(?TABLE) of
        undefined ->
            [];
        _ ->
            [{ConnId, Pid} || [ConnId, Pid] <- ets:match(?TABLE, {'$1', '_', '$2'})]
    end.

%% @doc Send `Msg` to every registered connection process. Dead pids are
%% skipped silently; absent registry is a no-op. Used for core
%% up/down notifications driving the rebind state machine.
-spec notify_all(term()) -> ok.
notify_all(Msg) ->
    lists:foreach(
      fun({_ConnId, Pid}) ->
          catch gen_statem:cast(Pid, Msg),
          ok
      end, members()),
    ok.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    _ = ets:new(?TABLE, [named_table, public, set,
                         {read_concurrency, true},
                         {write_concurrency, true}]),
    {ok, #{}}.

handle_call({register, ConnId, Pid}, _From, State) ->
    %% Overwrite path: release the previous owner's monitor first.
    case ets:lookup(?TABLE, ConnId) of
        [{ConnId, OldRef, _}] -> erlang:demonitor(OldRef, [flush]);
        [] -> ok
    end,
    MRef = erlang:monitor(process, Pid),
    ets:insert(?TABLE, {ConnId, MRef, Pid}),
    {reply, ok, State};
handle_call({unregister, ConnId}, _From, State) ->
    case ets:lookup(?TABLE, ConnId) of
        [{ConnId, MRef, _}] ->
            erlang:demonitor(MRef, [flush]),
            ets:delete(?TABLE, ConnId);
        [] ->
            ok
    end,
    {reply, ok, State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', MRef, process, _Pid, _Reason}, State) ->
    %% Connection died without unregistering: reap its row.
    catch ets:match_delete(?TABLE, {'_', MRef, '_'}),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    catch ets:delete(?TABLE),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
