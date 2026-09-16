%% @doc EUnit coverage for PERF-07 socket tuning.
%%
%% Asserts the opt lists used at each hot-path socket site carry
%% `nodelay' plus the chosen buffer sizes.
-module(indra_sockopts_tests).

-include_lib("eunit/include/eunit.hrl").

listener_sock_opts_nodelay_test() ->
    Opts = indra_listener:listen_sock_opts(),
    ?assert(lists:member({nodelay, true}, Opts)),
    ?assert(lists:member({recbuf, 65536}, Opts)),
    ?assert(lists:member({sndbuf, 65536}, Opts)).

conn_sock_opts_nodelay_test() ->
    Opts = indra_conn:conn_sock_opts(),
    ?assert(lists:member({nodelay, true}, Opts)),
    ?assert(lists:member({recbuf, 65536}, Opts)),
    ?assert(lists:member({sndbuf, 65536}, Opts)).

brokerlink_sock_opts_nodelay_test() ->
    Opts = indra_brokerlink:brokerlink_sock_opts(),
    ?assert(lists:member({nodelay, true}, Opts)),
    ?assert(lists:member({recbuf, 65536}, Opts)),
    ?assert(lists:member({sndbuf, 65536}, Opts)).

%% Live check: an accepted client socket actually runs with nodelay set.
accepted_socket_has_nodelay_test() ->
    {ok, LSock} = gen_tcp:listen(0, indra_listener:listen_sock_opts()),
    {ok, Port} = inet:port(LSock),
    Parent = self(),
    spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        ok = inet:setopts(Sock, indra_conn:conn_sock_opts()),
        {ok, Got} = inet:getopts(Sock, [nodelay, recbuf, sndbuf]),
        Parent ! {sock_opts, Got},
        gen_tcp:close(Sock)
    end),
    {ok, Client} = gen_tcp:connect("127.0.0.1", Port,
                                   [binary, {packet, raw}, {active, false}],
                                   2000),
    try
        receive
            {sock_opts, Got} ->
                ?assertEqual(true, proplists:get_value(nodelay, Got)),
                ?assert(proplists:get_value(recbuf, Got) >= 65536),
                ?assert(proplists:get_value(sndbuf, Got) >= 65536)
        after 5000 ->
            error(sock_opts_timeout)
        end
    after
        gen_tcp:close(Client),
        gen_tcp:close(LSock)
    end.
