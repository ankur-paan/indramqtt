-module(indra_edge_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    indra_edge_sup:start_link().

stop(_State) ->
    ok.
