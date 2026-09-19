%% @doc EUnit coverage for PERF-10 edge send-failure accounting.
%%
%% Drives the PublishOut socket-send failure path with a deterministically
%% dead client socket and asserts exactly one counted drop (and nothing
%% else). Fails before PERF-10 (no counter is bumped on the path).
%% All tests are self-terminating: every socket is closed within the
%% test and no connection process is started.
-module(indra_drop_counter_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PUBLISH_OUT, 16#0021).

%%====================================================================
%% Send-failure drop counting
%%====================================================================

%% @doc A PublishOut frame that never reaches the peer (dead client
%% socket) stops the connection with exactly one counted send-failure
%% drop; the ingress shed counter stays untouched.
send_failure_counts_one_drop_test() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw}, {active, false}]),
    {ok, Port} = inet:port(LSock),
    {ok, Dead} = gen_tcp:connect("127.0.0.1", Port,
                                 [binary, {packet, raw}, {active, false}],
                                 2000),
    gen_tcp:close(Dead),
    gen_tcp:close(LSock),
    Data = #{sock => Dead,
             sockmod => gen_tcp,
             qos0_dropped => 0},
    Meta = indra_brokerlink:encode_publish_meta(<<"t">>, 0, 0, false, false),
    Header = #{opcode => ?PUBLISH_OUT},
    {stop, normal, Data1} =
        indra_conn:handle_event(cast, {broker_frame, Header, Meta, <<"x">>},
                                connected, Data),
    ?assertEqual(1, maps:get(send_failed_dropped, Data1)),
    ?assertEqual(0, maps:get(qos0_dropped, Data1)).
