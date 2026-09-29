-module(indra_edge_sup).
-behaviour(supervisor).

-export([start_link/0, init/1, start_brokerlink/1, start_brokerlink/2,
         start_listener/1, start_ws_listener/1, start_wss_listener/1,
         shard_count/0, shard_name/1]).

-define(SERVER, ?MODULE).
-define(BROKERLINK, indra_edge_brokerlink).
-define(DEFAULT_SHARDS, 4).
-define(MAX_SHARDS, 32).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% Children start in order: the connection registry, the BrokerLink
%% client to the Rust kernel, then the MQTT listener. Every accepted
%% connection needs the BrokerLink pid ({broker, Pid}), so the listener
%% is started only once that client is up. one_for_all restarts the
%% listener with the new pid whenever the BrokerLink client restarts.
%% @doc Number of BrokerLink shard clients (app env
%% `brokerlink_shards', default 4; valid range 1..32, anything else
%% falls back to the default).
-spec shard_count() -> pos_integer().
shard_count() ->
    case application:get_env(indra_edge, brokerlink_shards) of
        {ok, K} when is_integer(K), K >= 1, K =< ?MAX_SHARDS -> K;
        undefined -> ?DEFAULT_SHARDS;
        _ -> ?DEFAULT_SHARDS
    end.

%% @doc Registered name of shard N (1-based). Used only when the shard
%% count is greater than 1; a single shard keeps the historic
%% `indra_edge_brokerlink' name.
-spec shard_name(pos_integer()) -> atom().
shard_name(N) when is_integer(N), N >= 1 ->
    list_to_atom("indra_edge_brokerlink_" ++ integer_to_list(N)).

init([]) ->
    SupFlags = #{strategy => one_for_all,
                 intensity => 10,
                 period => 5},
    MqttPort = application:get_env(indra_edge, mqtt_port, 1883),
    WsEnabled = application:get_env(indra_edge, ws_enabled, true),
    WsPort = application:get_env(indra_edge, ws_port, 8083),
    WsPath = application:get_env(indra_edge, ws_path, "/mqtt"),
    %% `wss' is opt-in (default disabled): without configured
    %% certificate material the listener cannot start, and a default-on
    %% listener would fail every boot that has no certs. The M1-03
    %% schema owns the final option names.
    WssEnabled = application:get_env(indra_edge, wss_enabled, false),
    WssPort = application:get_env(indra_edge, wss_port, 8084),
    WssPath = application:get_env(indra_edge, wss_path, "/mqtt"),
    WssCert = application:get_env(indra_edge, wss_certfile, undefined),
    WssKey = application:get_env(indra_edge, wss_keyfile, undefined),
    KernelHost = application:get_env(indra_edge, kernel_host, "127.0.0.1"),
    KernelPort = application:get_env(indra_edge, kernel_port, 18883),
    LinkOpts = [{transport, tcp},
                {host, KernelHost},
                {port, KernelPort},
                {reconnect, true}],
    Shards = shard_count(),
    BrokerSpecs = shard_specs(Shards, LinkOpts),
    ChildSpecs = [#{id => indra_conn_registry,
                    start => {indra_conn_registry, start_link, []},
                    restart => permanent,
                    shutdown => 5000,
                    type => worker,
                    modules => [indra_conn_registry]}] ++
                 BrokerSpecs ++
                 [#{id => indra_listener,
                    start => {?MODULE, start_listener, [[{port, MqttPort}]]},
                    restart => permanent,
                    shutdown => 5000,
                    type => worker,
                    modules => [indra_listener]}] ++
                 ws_child_spec(WsEnabled, WsPort, WsPath) ++
                 wss_child_spec(WssEnabled, WssPort, WssPath, WssCert, WssKey),
    {ok, {SupFlags, ChildSpecs}}.

%% @private WS listener child: runs beside TCP/TLS, never instead of
%% them. Disabled only when the operator sets `ws_enabled' to false;
%% the M1-03 schema owns the final option names.
ws_child_spec(false, _Port, _Path) ->
    [];
ws_child_spec(_, Port, Path) ->
    [#{id => indra_ws_listener,
       start => {?MODULE, start_ws_listener, [[{port, Port}, {path, Path}]]},
       restart => permanent,
       shutdown => 5000,
       type => worker,
       modules => [indra_ws_listener]}].

%% @private WSS listener child: the TLS WS listener beside plaintext
%% WS. Runs only when the operator enables `wss_enabled' with
%% `wss_certfile' and `wss_keyfile'; missing material fails the child
%% (and the boot) closed, never as plaintext. Certificate rotation
%% needs a restart: neither this listener nor the TCP/TLS listener
%% reloads material in place. The M1-03 schema owns the final names.
wss_child_spec(false, _Port, _Path, _Cert, _Key) ->
    [];
wss_child_spec(_, Port, Path, undefined, _Key) ->
    [#{id => indra_wss_listener,
       start => {?MODULE, start_wss_listener,
                 [[{transport, ssl}, {port, Port}, {path, Path}]]},
       restart => permanent,
       shutdown => 5000,
       type => worker,
       modules => [indra_ws_listener]}];
wss_child_spec(_, Port, Path, _Cert, undefined) ->
    [#{id => indra_wss_listener,
       start => {?MODULE, start_wss_listener,
                 [[{transport, ssl}, {port, Port}, {path, Path}]]},
       restart => permanent,
       shutdown => 5000,
       type => worker,
       modules => [indra_ws_listener]}];
wss_child_spec(_, Port, Path, Cert, Key) ->
    [#{id => indra_wss_listener,
       start => {?MODULE, start_wss_listener,
                 [[{transport, ssl}, {port, Port}, {path, Path},
                   {certfile, Cert}, {keyfile, Key}]]},
       restart => permanent,
       shutdown => 5000,
       type => worker,
       modules => [indra_ws_listener]}].
%% @private One child spec per shard. K = 1 keeps the historic child id
%% so supervision behaviour is exactly as before.
shard_specs(1, LinkOpts) ->
    [#{id => indra_brokerlink,
       start => {?MODULE, start_brokerlink, [LinkOpts]},
       restart => permanent,
       shutdown => 5000,
       type => worker,
       modules => [indra_brokerlink]}];
shard_specs(K, LinkOpts) ->
    [#{id => {indra_brokerlink, N},
       start => {?MODULE, start_brokerlink, [LinkOpts, N]},
       restart => permanent,
       shutdown => 5000,
       type => worker,
       modules => [indra_brokerlink]} || N <- lists:seq(1, K)].

%% @doc Start the BrokerLink client and register it so the listener
%% child can hand its pid to every connection.
start_brokerlink(Opts) ->
    case indra_brokerlink:start_link(Opts) of
        {ok, Pid} ->
            true = register(?BROKERLINK, Pid),
            announce_shard(Pid),
            {ok, Pid};
        Other ->
            Other
    end.

%% @doc Start one BrokerLink shard client (N is 1-based) and register
%% it under its distinct shard name.
start_brokerlink(Opts, N) ->
    case indra_brokerlink:start_link(Opts) of
        {ok, Pid} ->
            true = register(shard_name(N), Pid),
            announce_shard(Pid),
            {ok, Pid};
        Other ->
            Other
    end.

%% @private Re-announce a freshly registered shard pid. The brokerlink
%% client already broadcasts from init, but that fires before this
%% registration; connections disambiguate restarts through the
%% registered name (see indra_conn:classify_unknown/2), so repeat the
%% announcement once the name resolves to the new pid. Total when the
%% registry is absent (early boot, unit tests).
announce_shard(Pid) ->
    catch indra_conn_registry:notify_all({broker_up, Pid}),
    ok.

%% @doc Start the MQTT listener wired to the running BrokerLink shard
%% clients. A single shard hands `{broker, Pid}' exactly as before;
%% K > 1 hands `{broker, [Pid1, ..., PidK]}' so each connection can pin
%% to one shard by `conn_id rem K'.
start_listener(Opts) ->
    case shard_count() of
        1 ->
            case whereis(?BROKERLINK) of
                undefined ->
                    {error, brokerlink_not_running};
                Broker ->
                    indra_listener:start_link([{conn, [{broker, Broker}]} | Opts])
            end;
        K ->
            Brokers = [whereis(shard_name(N)) || N <- lists:seq(1, K)],
            case lists:member(undefined, Brokers) of
                true ->
                    {error, brokerlink_not_running};
                false ->
                    indra_listener:start_link([{conn, [{broker, Brokers}]} | Opts])
            end
    end.

%% @doc Start the WS listener wired to the running BrokerLink shard
%% clients, exactly like {@link start_listener/1}. The WS handshake and
%% framing stay on the edge; the kernel bind path is identical.
start_ws_listener(Opts) ->
    case shard_count() of
        1 ->
            case whereis(?BROKERLINK) of
                undefined ->
                    {error, brokerlink_not_running};
                Broker ->
                    indra_ws_listener:start_link([{conn, [{broker, Broker}]} | Opts])
            end;
        K ->
            Brokers = [whereis(shard_name(N)) || N <- lists:seq(1, K)],
            case lists:member(undefined, Brokers) of
                true ->
                    {error, brokerlink_not_running};
                false ->
                    indra_ws_listener:start_link([{conn, [{broker, Brokers}]} | Opts])
            end
    end.

%% @doc Start the WSS listener wired to the running BrokerLink shard
%% clients, exactly like {@link start_ws_listener/1} with the TLS
%% options (`{transport, ssl}', `{certfile, _}', `{keyfile, _}')
%% already in `Opts'. TLS terminates on the edge; the kernel bind path
%% is identical to plaintext WS.
start_wss_listener(Opts) ->
    case shard_count() of
        1 ->
            case whereis(?BROKERLINK) of
                undefined ->
                    {error, brokerlink_not_running};
                Broker ->
                    indra_ws_listener:start_link([{conn, [{broker, Broker}]} | Opts])
            end;
        K ->
            Brokers = [whereis(shard_name(N)) || N <- lists:seq(1, K)],
            case lists:member(undefined, Brokers) of
                true ->
                    {error, brokerlink_not_running};
                false ->
                    indra_ws_listener:start_link([{conn, [{broker, Brokers}]} | Opts])
            end
    end.
