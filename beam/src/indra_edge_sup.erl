-module(indra_edge_sup).
-behaviour(supervisor).

-export([start_link/0, init/1, start_brokerlink/1, start_listener/1]).

-define(SERVER, ?MODULE).
-define(BROKERLINK, indra_edge_brokerlink).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% Children start in order: the connection registry, the BrokerLink
%% client to the Rust kernel, then the MQTT listener. Every accepted
%% connection needs the BrokerLink pid ({broker, Pid}), so the listener
%% is started only once that client is up. one_for_all restarts the
%% listener with the new pid whenever the BrokerLink client restarts.
init([]) ->
    SupFlags = #{strategy => one_for_all,
                 intensity => 10,
                 period => 5},
    MqttPort = application:get_env(indra_edge, mqtt_port, 1883),
    KernelHost = application:get_env(indra_edge, kernel_host, "127.0.0.1"),
    KernelPort = application:get_env(indra_edge, kernel_port, 18883),
    LinkOpts = [{transport, tcp},
                {host, KernelHost},
                {port, KernelPort},
                {reconnect, true}],
    ChildSpecs = [#{id => indra_conn_registry,
                    start => {indra_conn_registry, start_link, []},
                    restart => permanent,
                    shutdown => 5000,
                    type => worker,
                    modules => [indra_conn_registry]},
                  #{id => indra_brokerlink,
                    start => {?MODULE, start_brokerlink, [LinkOpts]},
                    restart => permanent,
                    shutdown => 5000,
                    type => worker,
                    modules => [indra_brokerlink]},
                  #{id => indra_listener,
                    start => {?MODULE, start_listener, [[{port, MqttPort}]]},
                    restart => permanent,
                    shutdown => 5000,
                    type => worker,
                    modules => [indra_listener]}],
    {ok, {SupFlags, ChildSpecs}}.

%% @doc Start the BrokerLink client and register it so the listener
%% child can hand its pid to every connection.
start_brokerlink(Opts) ->
    case indra_brokerlink:start_link(Opts) of
        {ok, Pid} ->
            true = register(?BROKERLINK, Pid),
            {ok, Pid};
        Other ->
            Other
    end.

%% @doc Start the MQTT listener wired to the running BrokerLink client.
start_listener(Opts) ->
    case whereis(?BROKERLINK) of
        undefined ->
            {error, brokerlink_not_running};
        Broker ->
            indra_listener:start_link([{conn, [{broker, Broker}]} | Opts])
    end.
