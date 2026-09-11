-module(indra_edge_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{strategy => one_for_all,
                 intensity => 10,
                 period => 5},
    MqttPort = application:get_env(indra_edge, mqtt_port, 1883),
    ChildSpecs = [#{id => indra_conn_registry,
                    start => {indra_conn_registry, start_link, []},
                    restart => permanent,
                    shutdown => 5000,
                    type => worker,
                    modules => [indra_conn_registry]},
                  #{id => indra_listener,
                    start => {indra_listener, start_link, [[{port, MqttPort}]]},
                    restart => permanent,
                    shutdown => 5000,
                    type => worker,
                    modules => [indra_listener]}],
    {ok, {SupFlags, ChildSpecs}}.
