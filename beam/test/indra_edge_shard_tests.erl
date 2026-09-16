%% @doc EUnit tests for PERF-01 edge BrokerLink sharding.
%%
%% Covers the supervisor shard count/config, the `conn_id rem K'
%% pinning in {@link indra_conn}, and per-shard parallelism under
%% concurrent publish load. All tests are self-terminating: every
%% socket is closed and every process stopped within the test.
-module(indra_edge_shard_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).

%%====================================================================
%% Pinning: pure distribution
%%====================================================================

pick_shard_distributes_evenly_test() ->
    Shards = [spawn(fun() -> ok end) || _ <- lists:seq(1, 4)],
    %% Use pids only as markers; pick_shard never touches them.
    Counts = lists:foldl(
        fun(ConnId, Acc) ->
            Pid = indra_conn:pick_shard(ConnId, Shards),
            Idx = index_of(Pid, Shards),
            maps:update_with(Idx, fun(V) -> V + 1 end, 1, Acc)
        end, #{}, lists:seq(0, 999)),
    ?assertEqual(#{0 => 250, 1 => 250, 2 => 250, 3 => 250}, Counts),
    %% Spot-check the rem mapping itself.
    ?assertEqual(lists:nth(1, Shards), indra_conn:pick_shard(0, Shards)),
    ?assertEqual(lists:nth(2, Shards), indra_conn:pick_shard(1, Shards)),
    ?assertEqual(lists:nth(1, Shards), indra_conn:pick_shard(8, Shards)).

single_shard_pins_everything_test() ->
    [Only] = [spawn(fun() -> ok end)],
    Shards = [Only],
    lists:foreach(
        fun(ConnId) ->
            ?assertEqual(Only, indra_conn:pick_shard(ConnId, Shards))
        end, lists:seq(0, 99)),
    ?assertEqual(0, indra_conn:shard_index(12345, 1)).

%%====================================================================
%% Pinning: live connections pin by conn_id
%%====================================================================

conn_pins_to_shard_by_conn_id_test() ->
    {ok, MockA} = mock_broker:start_link(),
    {ok, MockB} = mock_broker:start_link(),
    Shards = [MockA, MockB],
    {LSockA, PortA, ClientA, ConnA} = setup_shard_conn(0, Shards),
    {LSockB, PortB, ClientB, ConnB} = setup_shard_conn(1, Shards),
    _ = PortA,
    _ = PortB,
    try
        {connected, DataA} = wait_state(ConnA, connected),
        {connected, DataB} = wait_state(ConnB, connected),
        ?assertEqual(MockA, maps:get(broker, DataA)),
        ?assertEqual(MockB, maps:get(broker, DataB)),
        ?assertEqual(0, maps:get(shard, DataA)),
        ?assertEqual(1, maps:get(shard, DataB)),
        %% Each bind reached its own shard only.
        ?assertEqual(1, length([F || F <- mock_broker:sent(MockA),
                                    maps:get(conn_id, F) =:= 1000])),
        ?assertEqual(1, length([F || F <- mock_broker:sent(MockB),
                                    maps:get(conn_id, F) =:= 1001])),
        ?assertEqual([], [F || F <- mock_broker:sent(MockA),
                               maps:get(conn_id, F) =:= 1001]),
        ?assertEqual([], [F || F <- mock_broker:sent(MockB),
                               maps:get(conn_id, F) =:= 1000])
    after
        teardown_shard(LSockA, MockA, ClientA, ConnA),
        teardown_shard(LSockB, MockB, ClientB, ConnB)
    end.

%% Other-shard announcements are ignored: the pin never changes.
conn_ignores_other_shard_broker_up_test() ->
    {ok, MockA} = mock_broker:start_link(),
    {ok, MockB} = mock_broker:start_link(),
    Shards = [MockA, MockB],
    {LSock, _Port, Client, Conn} = setup_shard_conn(0, Shards),
    try
        {connected, Data} = wait_state(Conn, connected),
        ?assertEqual(MockA, maps:get(broker, Data)),
        gen_statem:cast(Conn, {broker_up, MockB}),
        timer:sleep(200),
        {connected, Data1} = wait_state(Conn, connected),
        ?assertEqual(MockA, maps:get(broker, Data1)),
        %% No rebind was emitted to the other shard.
        ?assertEqual(1, length(mock_broker:sent(MockA))),
        ?assertEqual(0, length(mock_broker:sent(MockB)))
    after
        teardown_shard(LSock, MockA, Client, Conn),
        catch mock_broker:stop(MockB)
    end.

%% Scoped down: another shard's outage never parks us; our own
%% shard's down holds for the rebind sweep (PERF-03 Required 2: no
%% rebind storm, no missed hold).
other_shard_broker_down_leaves_conns_connected_test() ->
    {ok, MockA} = mock_broker:start_link(),
    {ok, MockB} = mock_broker:start_link(),
    Shards = [MockA, MockB],
    {LSock, _Port, Client, Conn} = setup_shard_conn(0, Shards),
    try
        {connected, Data} = wait_state(Conn, connected),
        ?assertEqual(MockA, maps:get(broker, Data)),
        %% Other shard's down: ignored, still connected, no traffic.
        gen_statem:cast(Conn, {broker_down, MockB}),
        timer:sleep(200),
        {connected, Data1} = wait_state(Conn, connected),
        ?assertEqual(MockA, maps:get(broker, Data1)),
        ?assertEqual(1, length(mock_broker:sent(MockA))),
        ?assertEqual(0, length(mock_broker:sent(MockB))),
        %% Unknown pid's down: ignored as well, never a blind hold.
        {ok, Spare} = mock_broker:start_link(),
        try
            gen_statem:cast(Conn, {broker_down, Spare}),
            timer:sleep(200),
            ?assertMatch({connected, _}, wait_state(Conn, connected))
        after
            catch mock_broker:stop(Spare)
        end,
        %% Own shard's down: hold for the sweep.
        gen_statem:cast(Conn, {broker_down, MockA}),
        ?assertMatch({await_core, _}, wait_state(Conn, await_core))
    after
        teardown_shard(LSock, MockA, Client, Conn),
        catch mock_broker:stop(MockB)
    end.

%%====================================================================
%% Parallelism: concurrent publishes split across shard mailboxes
%%====================================================================

concurrent_publishes_split_across_shards_test() ->
    {ok, MockA} = mock_broker:start_link(),
    {ok, MockB} = mock_broker:start_link(),
    Shards = [MockA, MockB],
    Conns = [setup_shard_conn(ConnId, Shards) || ConnId <- lists:seq(0, 7)],
    try
        Pids = [Conn || {_, _, _, Conn} <- Conns],
        lists:foreach(
            fun(Conn) -> ?assertMatch({connected, _}, wait_state(Conn, connected)) end,
            Pids),
        Parent = self(),
        %% Fire one QoS 0 publish per conn in parallel.
        lists:foreach(
            fun({{_LSock, _Port, Client, _Conn}, N}) ->
                spawn(fun() ->
                    ok = gen_tcp:send(Client, publish_packet(<<"t">>, 0, 16#30, <<"p">>)),
                    Parent ! {pub_sent, N}
                end)
            end, lists:zip(Conns, lists:seq(1, 8))),
        lists:foreach(
            fun(N) ->
                receive {pub_sent, N} -> ok
                after ?RECV_TIMEOUT -> error({pub_timeout, N})
                end
            end, lists:seq(1, 8)),
        %% 8 binds + 8 publishes total, split 8/8 across shards.
        wait_total_frames([MockA, MockB], 16),
        SentA = mock_broker:sent(MockA),
        SentB = mock_broker:sent(MockB),
        ?assertEqual(8, length(SentA)),
        ?assertEqual(8, length(SentB)),
        ?assertEqual(4, length([F || F <- SentA, maps:get(opcode, F) =:= 16#0020])),
        ?assertEqual(4, length([F || F <- SentB, maps:get(opcode, F) =:= 16#0020])),
        %% Per-shard mailboxes drain to ~0: nothing serializes behind one
        %% queue. Assert each shard, not just the total.
        ?assert(mailbox_depth(MockA) =< 1),
        ?assert(mailbox_depth(MockB) =< 1)
    after
        lists:foreach(
            fun({LSock, _, Client, Conn}) ->
                catch indra_conn:stop(Conn),
                catch gen_tcp:close(Client),
                catch gen_tcp:close(LSock)
            end, Conns),
        catch mock_broker:stop(MockA),
        catch mock_broker:stop(MockB)
    end.

%%====================================================================
%% Own-shard restart: adopt the replacement for the pinned slot
%%====================================================================

%% A restarted own shard is recoverable: the replacement (registered
%% under our shard name) triggers a rebind and the pin never moves.
own_shard_restart_rebinds_connected_test() ->
    {ok, MockA} = mock_broker:start_link(),
    {ok, MockB} = mock_broker:start_link(),
    Shards = [MockA, MockB],
    {LSock, _Port, Client, Conn} = setup_shard_conn(0, Shards),
    {ok, OwnNew} = mock_broker:start_link(),
    register_shard(1, OwnNew),
    try
        {connected, Data} = wait_state(Conn, connected),
        ?assertEqual(MockA, maps:get(broker, Data)),
        ok = mock_broker:stop(MockA),
        gen_statem:cast(Conn, {broker_up, OwnNew}),
        %% Rebind went to the replacement: same client, forced
        %% non-clean, next seq.
        [Rebind] = wait_frames(OwnNew, 1),
        ?assertEqual(16#0010, maps:get(opcode, Rebind)),
        ?assertEqual(1000, maps:get(conn_id, Rebind)),
        {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Rebind)),
        ?assertEqual(<<"shard-1000">>, maps:get(client_id, Bind)),
        ?assertEqual(false, maps:get(clean_start, Bind)),
        {await_core, Data1} = wait_state(Conn, await_core),
        %% Pin kept, slot adopted.
        ?assertEqual(OwnNew, maps:get(broker, Data1)),
        ?assertEqual([OwnNew, MockB], maps:get(brokers, Data1)),
        ?assertEqual(0, maps:get(shard, Data1)),
        %% Core kept state: straight back to connected, no CONNACK repeat.
        ok = indra_conn:broker_frame(
               Conn, #{opcode => 16#0011},
               indra_brokerlink:encode_session_binding_meta(77, true, 0), <<>>),
        ?assertMatch({connected, _}, wait_state(Conn, connected)),
        ?assertEqual({error, timeout}, gen_tcp:recv(Client, 0, 200))
    after
        unregister_shard(1),
        catch mock_broker:stop(OwnNew),
        teardown_shard(LSock, MockA, Client, Conn),
        catch mock_broker:stop(MockB)
    end.

%% Another shard's restart news never pulls us off our pin: with our
%% own shard dead we adopt the registry's pid for OUR slot, not the
%% announcer.
other_shard_news_adopts_own_slot_test() ->
    {ok, MockA} = mock_broker:start_link(),
    {ok, MockB} = mock_broker:start_link(),
    Shards = [MockA, MockB],
    {LSock, _Port, Client, Conn} = setup_shard_conn(0, Shards),
    {ok, OwnNew} = mock_broker:start_link(),
    {ok, OtherNew} = mock_broker:start_link(),
    register_shard(1, OwnNew),
    register_shard(2, OtherNew),
    try
        ?assertMatch({connected, _}, wait_state(Conn, connected)),
        ok = mock_broker:stop(MockA),
        %% The other shard's replacement announces first.
        gen_statem:cast(Conn, {broker_up, OtherNew}),
        [Rebind] = wait_frames(OwnNew, 1),
        ?assertEqual(16#0010, maps:get(opcode, Rebind)),
        ?assertEqual(1000, maps:get(conn_id, Rebind)),
        timer:sleep(200),
        %% Nothing collapsed onto the announcer.
        ?assertEqual([], mock_broker:sent(OtherNew)),
        {await_core, Data1} = wait_state(Conn, await_core),
        ?assertEqual(OwnNew, maps:get(broker, Data1)),
        ?assertEqual([OwnNew, MockB], maps:get(brokers, Data1)),
        ?assertEqual(0, maps:get(shard, Data1))
    after
        unregister_shard(1),
        unregister_shard(2),
        catch mock_broker:stop(OwnNew),
        catch mock_broker:stop(OtherNew),
        teardown_shard(LSock, MockA, Client, Conn),
        catch mock_broker:stop(MockB)
    end.

%% An unknown pid with our shard dead but nothing registered yet is
%% deferred, not adopted: the supervisor's post-registration
%% announcement drives the adoption.
unknown_announcement_before_registration_defers_test() ->
    {ok, MockA} = mock_broker:start_link(),
    {ok, MockB} = mock_broker:start_link(),
    Shards = [MockA, MockB],
    {LSock, _Port, Client, Conn} = setup_shard_conn(0, Shards),
    {ok, Spare} = mock_broker:start_link(),
    unregister_shard(1),
    unregister_shard(2),
    try
        ?assertMatch({connected, _}, wait_state(Conn, connected)),
        ok = mock_broker:stop(MockA),
        gen_statem:cast(Conn, {broker_up, Spare}),
        timer:sleep(300),
        %% No blind adopt: no rebind, pin still on the dead pid.
        ?assertEqual([], mock_broker:sent(Spare)),
        {connected, Data} = wait_state(Conn, connected),
        ?assertEqual(MockA, maps:get(broker, Data)),
        %% The post-registration announcement adopts.
        register_shard(1, Spare),
        gen_statem:cast(Conn, {broker_up, Spare}),
        [_Rebind] = wait_frames(Spare, 1),
        ?assertMatch({await_core, _}, wait_state(Conn, await_core))
    after
        unregister_shard(1),
        unregister_shard(2),
        catch mock_broker:stop(Spare),
        teardown_shard(LSock, MockA, Client, Conn),
        catch mock_broker:stop(MockB)
    end.

%% Mid-handshake restart: the pending bind is re-driven on the
%% replacement for our pinned slot.
own_shard_restart_resends_pending_bind_test() ->
    {ok, MockA} = mock_broker:start_link(),
    {ok, MockB} = mock_broker:start_link(),
    Shards = [MockA, MockB],
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Parent = self(),
    spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Conn} = indra_conn:start_link(
            Sock, [{broker, Shards}, {conn_id, 1000}]),
        ok = gen_tcp:controlling_process(Sock, Conn),
        gen_statem:cast(Conn, takeover),
        Parent ! {conn_ready, Conn}
    end),
    {ok, Client} = gen_tcp:connect("127.0.0.1", Port,
                                   [binary, {packet, raw}, {active, false}],
                                   5000),
    Conn = receive {conn_ready, C} -> C
           after 5000 -> error(conn_not_ready)
           end,
    {ok, OwnNew} = mock_broker:start_link(),
    register_shard(1, OwnNew),
    try
        ok = gen_tcp:send(Client, connect_packet(<<"shard-1000">>, true, 60)),
        wait_bind_on(MockA, 1000),
        ok = mock_broker:stop(MockA),
        gen_statem:cast(Conn, {broker_up, OwnNew}),
        %% Pending bind re-driven on the replacement with the next seq.
        [Rebind] = wait_frames(OwnNew, 1),
        ?assertEqual(16#0010, maps:get(opcode, Rebind)),
        ?assertEqual(1000, maps:get(conn_id, Rebind)),
        ?assertEqual(2, maps:get(seq_no, Rebind)),
        {await_connect, Data1} = wait_state(Conn, await_connect),
        ?assertEqual(OwnNew, maps:get(broker, Data1)),
        ?assertEqual([OwnNew, MockB], maps:get(brokers, Data1))
    after
        unregister_shard(1),
        catch mock_broker:stop(OwnNew),
        catch indra_conn:stop(Conn),
        catch gen_tcp:close(Client),
        catch gen_tcp:close(LSock),
        catch mock_broker:stop(MockA),
        catch mock_broker:stop(MockB)
    end.

%%====================================================================
%% PERF-03: shard-scoped rebind sweep over K clients
%%====================================================================

%% Restarting one shard rebinds exactly the conns pinned to it (with
%% silent resubscribe of every tracked sub); conns on the surviving
%% shard send nothing and never adopt the replacement pid.
shard_restart_sweep_rebinds_only_pinned_with_resubscribe_test() ->
    {ok, MockA} = mock_broker:start_link(),
    {ok, MockB} = mock_broker:start_link(),
    Shards = [MockA, MockB],
    {LSockA0, _, ClientA0, ConnA0} = setup_shard_conn(0, Shards),
    {LSockA1, _, ClientA1, ConnA1} = setup_shard_conn(2, Shards),
    {LSockB0, _, ClientB0, ConnB0} = setup_shard_conn(1, Shards),
    {LSockB1, _, ClientB1, ConnB1} = setup_shard_conn(3, Shards),
    {ok, OwnNew} = mock_broker:start_link(),
    try
        Pinned = [{1000, ClientA0, ConnA0, <<"sweep/0">>},
                  {1002, ClientA1, ConnA1, <<"sweep/2">>}],
        Unpinned = [{1001, ClientB0, ConnB0, <<"sweep/1">>},
                    {1003, ClientB1, ConnB1, <<"sweep/3">>}],
        %% Every conn subscribes (packet id 7, own filter) and gets its
        %% SUBACK on the socket, so each has exactly one tracked sub.
        lists:foreach(
            fun({BrokerConnId, Client, Conn, Filter}) ->
                Expected = indra_conn:pick_shard(BrokerConnId, Shards),
                ok = gen_tcp:send(Client, subscribe_packet(7, [{Filter, 1}])),
                wait_sub_on(Expected, BrokerConnId, 7),
                ok = indra_conn:broker_frame(
                       Conn, #{opcode => 16#0031},
                       indra_brokerlink:encode_suback_meta(7, [1]), <<>>),
                ?assertEqual(<<16#90, 16#03, 16#00, 16#07, 16#01>>,
                             recv_exact(Client, 5))
            end, Pinned ++ Unpinned),
        BaseB = length(mock_broker:sent(MockB)),
        %% Kill shard 0; the supervisor registers the replacement under
        %% our slot name before announcing it.
        ok = mock_broker:stop(MockA),
        register_shard(1, OwnNew),
        lists:foreach(
            fun({_, _, Conn, _}) ->
                gen_statem:cast(Conn, {broker_up, OwnNew})
            end, [hd(Pinned), hd(tl(Pinned)),
                  hd(Unpinned), hd(tl(Unpinned))]),
        %% Exactly the two pinned conns rebind on the replacement:
        %% same client, forced non-clean.
        Rebinds = wait_binds_on(OwnNew, [1000, 1002]),
        ?assertEqual(2, length(Rebinds)),
        lists:foreach(
            fun(R) ->
                {ok, Bind} = indra_brokerlink:decode_bind_meta(
                               maps:get(meta, R)),
                ?assertEqual(false, maps:get(clean_start, Bind))
            end, Rebinds),
        {await_core, DataA0} = wait_state(ConnA0, await_core),
        {await_core, DataA1} = wait_state(ConnA1, await_core),
        %% Pins kept, slot adopted; never collapsed onto the survivor.
        ?assertEqual(OwnNew, maps:get(broker, DataA0)),
        ?assertEqual(OwnNew, maps:get(broker, DataA1)),
        ?assertEqual([OwnNew, MockB], maps:get(brokers, DataA0)),
        ?assertEqual([OwnNew, MockB], maps:get(brokers, DataA1)),
        ?assertEqual(0, maps:get(shard, DataA0)),
        %% Unpinned conns are unaffected: still connected on MockB, and
        %% no rebind traffic reached the surviving shard.
        timer:sleep(300),
        ?assertEqual(BaseB, length(mock_broker:sent(MockB))),
        {connected, DataB0} = wait_state(ConnB0, connected),
        {connected, DataB1} = wait_state(ConnB1, connected),
        ?assertEqual(MockB, maps:get(broker, DataB0)),
        ?assertEqual(MockB, maps:get(broker, DataB1)),
        %% Core lost state: every pinned conn resubscribes its tracked
        %% sub on the owning shard; the echoes stay silent.
        lists:foreach(
            fun({_, _, Conn, _}) ->
                ok = indra_conn:broker_frame(
                       Conn, #{opcode => 16#0011},
                       indra_brokerlink:encode_session_binding_meta(
                         77, false, 0), <<>>)
            end, Pinned),
        Resubs = wait_subs_on(OwnNew, [{1000, 7}, {1002, 7}]),
        ?assertEqual([<<"sweep/0">>, <<"sweep/2">>],
                     lists:sort([Filter || {_, Filter} <- Resubs])),
        lists:foreach(
            fun({BrokerConnId, Client, Conn, _}) ->
                ok = indra_conn:broker_frame(
                       Conn, #{opcode => 16#0031},
                       indra_brokerlink:encode_suback_meta(7, [1]), <<>>),
                ?assertMatch({connected, _}, wait_state(Conn, connected)),
                ?assertEqual({error, timeout},
                             gen_tcp:recv(Client, 0, 200)),
                %% Sanity: the conn id on the resub matches the pinned
                %% conn, i.e. traffic went to the owning shard.
                ?assert(lists:any(
                          fun(F) ->
                              maps:get(conn_id, F) =:= BrokerConnId
                          end, mock_broker:sent(OwnNew)))
            end, Pinned),
        %% Still nothing new on the surviving shard after the resubs.
        ?assertEqual(BaseB, length(mock_broker:sent(MockB))),
        ?assertMatch({connected, _}, wait_state(ConnB0, connected)),
        ?assertMatch({connected, _}, wait_state(ConnB1, connected))
    after
        unregister_shard(1),
        unregister_shard(2),
        catch mock_broker:stop(OwnNew),
        teardown_shard(LSockA0, MockA, ClientA0, ConnA0),
        teardown_shard(LSockA1, MockA, ClientA1, ConnA1),
        teardown_shard(LSockB0, MockB, ClientB0, ConnB0),
        teardown_shard(LSockB1, MockB, ClientB1, ConnB1)
    end.

%%====================================================================
%% Supervisor shard config
%%====================================================================

shard_count_default_is_four_test() ->
    Old = application:get_env(indra_edge, brokerlink_shards),
    application:unset_env(indra_edge, brokerlink_shards),
    try
        ?assertEqual(4, indra_edge_sup:shard_count())
    after
        restore_env(Old)
    end.

shard_count_valid_range_test() ->
    Old = application:get_env(indra_edge, brokerlink_shards),
    try
        lists:foreach(
            fun(K) ->
                ok = application:set_env(indra_edge, brokerlink_shards, K),
                ?assertEqual(K, indra_edge_sup:shard_count())
            end, [1, 2, 4, 32])
    after
        restore_env(Old)
    end.

shard_count_out_of_range_falls_back_test() ->
    Old = application:get_env(indra_edge, brokerlink_shards),
    try
        lists:foreach(
            fun(Bad) ->
                ok = application:set_env(indra_edge, brokerlink_shards, Bad),
                ?assertEqual(4, indra_edge_sup:shard_count())
            end, [0, -1, 33, 100, "4", 4.0, undefined])
    after
        restore_env(Old)
    end.

shard_names_distinct_test() ->
    Names = [indra_edge_sup:shard_name(N) || N <- lists:seq(1, 4)],
    ?assertEqual(4, length(lists:usort(Names))).

sup_init_starts_k_shards_test() ->
    Old = application:get_env(indra_edge, brokerlink_shards),
    try
        ok = application:set_env(indra_edge, brokerlink_shards, 1),
        {ok, {_, Kids1}} = indra_edge_sup:init([]),
        ?assertEqual(3, length(Kids1)),
        ok = application:set_env(indra_edge, brokerlink_shards, 4),
        {ok, {_, Kids4}} = indra_edge_sup:init([]),
        %% registry + 4 brokerlinks + listener.
        ?assertEqual(6, length(Kids4))
    after
        restore_env(Old)
    end.

%%====================================================================
%% Helpers
%%====================================================================

index_of(Pid, Shards) ->
    index_of(Pid, Shards, 0).

index_of(Pid, [Pid | _], N) -> N;
index_of(Pid, [_ | Rest], N) -> index_of(Pid, Rest, N + 1).

%% @private Register a mock as shard N's replacement, clearing any
%% stale entry first. Returns ok.
register_shard(N, Pid) ->
    Name = indra_edge_sup:shard_name(N),
    catch erlang:unregister(Name),
    true = register(Name, Pid),
    ok.

%% @private Clear shard N's registered replacement (no-op when absent).
unregister_shard(N) ->
    catch erlang:unregister(indra_edge_sup:shard_name(N)),
    ok.

restore_env(undefined) ->
    application:unset_env(indra_edge, brokerlink_shards);
restore_env({ok, V}) ->
    application:set_env(indra_edge, brokerlink_shards, V).

mailbox_depth(Pid) ->
    case process_info(Pid, message_queue_len) of
        {message_queue_len, N} -> N;
        undefined -> 0
    end.

wait_total_frames(Mocks, N) ->
    wait_total_frames(Mocks, N, 40).

wait_total_frames(_Mocks, _N, 0) ->
    error(broker_frame_timeout);
wait_total_frames(Mocks, N, Tries) ->
    Total = lists:sum([length(mock_broker:sent(M)) || M <- Mocks]),
    case Total >= N of
        true -> ok;
        false -> timer:sleep(50), wait_total_frames(Mocks, N, Tries - 1)
    end.

%% @private Wait until Mock records at least N frames, returns all.
wait_frames(Mock, N) ->
    wait_frames(Mock, N, 40).

wait_frames(_Mock, _N, 0) ->
    error(broker_frame_timeout);
wait_frames(Mock, N, Tries) ->
    case mock_broker:sent(Mock) of
        Frames when length(Frames) >= N -> Frames;
        _ -> timer:sleep(50), wait_frames(Mock, N, Tries - 1)
    end.

%% @private One handshaked conn pinned by ConnId into Shards. The
%% BrokerLink conn id is 1000 + ConnId so parallel tests never collide.
setup_shard_conn(ConnId, Shards) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    BrokerConnId = 1000 + ConnId,
    Parent = self(),
    spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Conn} = indra_conn:start_link(
            Sock, [{broker, Shards}, {conn_id, BrokerConnId}]),
        ok = gen_tcp:controlling_process(Sock, Conn),
        gen_statem:cast(Conn, takeover),
        Parent ! {conn_ready, Conn}
    end),
    {ok, Client} = gen_tcp:connect("127.0.0.1", Port,
                                   [binary, {packet, raw}, {active, false}],
                                   5000),
    Conn = receive {conn_ready, C} -> C
           after 5000 -> error(conn_not_ready)
           end,
    ClientId = <<"shard-", (integer_to_binary(BrokerConnId))/binary>>,
    ok = gen_tcp:send(Client, connect_packet(ClientId, true, 60)),
    %% Wait for the bind on the pinned shard first: answering before
    %% the edge processes CONNECT would hit `pending => undefined'.
    Expected = indra_conn:pick_shard(BrokerConnId, Shards),
    wait_bind_on(Expected, BrokerConnId),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    %% The bind lands on the pinned shard; answer the conn directly.
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = recv_exact(Client, 4),
    {LSock, Port, Client, Conn}.

%% @private Wait until Mock records a BindConnection for ConnId.
wait_bind_on(Mock, ConnId) ->
    wait_bind_on(Mock, ConnId, 40).

wait_bind_on(_Mock, _ConnId, 0) ->
    error(broker_frame_timeout);
wait_bind_on(Mock, ConnId, Tries) ->
    Found = [F || F <- mock_broker:sent(Mock),
                  maps:get(opcode, F) =:= 16#0010,
                  maps:get(conn_id, F) =:= ConnId],
    case Found of
        [_ | _] -> ok;
        [] -> timer:sleep(50), wait_bind_on(Mock, ConnId, Tries - 1)
    end.

%% @private Wait until Mock records BindConnection frames for every
%% conn id in ConnIds; returns the matching binds.
wait_binds_on(Mock, ConnIds) ->
    wait_binds_on(Mock, ConnIds, 40).

wait_binds_on(_Mock, _ConnIds, 0) ->
    error(broker_frame_timeout);
wait_binds_on(Mock, ConnIds, Tries) ->
    Found = [F || F <- mock_broker:sent(Mock),
                  maps:get(opcode, F) =:= 16#0010,
                  lists:member(maps:get(conn_id, F), ConnIds)],
    case length(Found) >= length(ConnIds) of
        true -> Found;
        false -> timer:sleep(50), wait_binds_on(Mock, ConnIds, Tries - 1)
    end.

%% @private Wait until Mock records a SubscribeIn for ConnId/PacketId.
wait_sub_on(Mock, ConnId, PacketId) ->
    wait_sub_on(Mock, ConnId, PacketId, 40).

wait_sub_on(_Mock, _ConnId, _PacketId, 0) ->
    error(broker_frame_timeout);
wait_sub_on(Mock, ConnId, PacketId, Tries) ->
    Found = [F || F <- mock_broker:sent(Mock),
                  maps:get(opcode, F) =:= 16#0030,
                  maps:get(conn_id, F) =:= ConnId,
                  subscribes_packet(F, PacketId)],
    case Found of
        [_ | _] -> ok;
        [] -> timer:sleep(50), wait_sub_on(Mock, ConnId, PacketId, Tries - 1)
    end.

%% @private Wait until Mock records SubscribeIn frames for every
%% {ConnId, PacketId} pair; returns [{ConnId, Filter}] decoded.
wait_subs_on(Mock, Pairs) ->
    wait_subs_on(Mock, Pairs, 40).

wait_subs_on(_Mock, _Pairs, 0) ->
    error(broker_frame_timeout);
wait_subs_on(Mock, Pairs, Tries) ->
    Found = lists:foldl(
        fun({ConnId, PacketId}, Acc) ->
            case [F || F <- mock_broker:sent(Mock),
                       maps:get(opcode, F) =:= 16#0030,
                       maps:get(conn_id, F) =:= ConnId,
                       subscribes_packet(F, PacketId)] of
                [F | _] ->
                    {ok, Meta} = indra_brokerlink:decode_subscribe_meta(
                                   maps:get(meta, F)),
                    [{Filter, _}] = maps:get(subscriptions, Meta),
                    [{ConnId, Filter} | Acc];
                [] ->
                    Acc
            end
        end, [], Pairs),
    case length(Found) >= length(Pairs) of
        true -> Found;
        false -> timer:sleep(50), wait_subs_on(Mock, Pairs, Tries - 1)
    end.

%% @private True when a SubscribeIn frame carries PacketId.
subscribes_packet(Frame, PacketId) ->
    case indra_brokerlink:decode_subscribe_meta(maps:get(meta, Frame)) of
        {ok, #{packet_id := PacketId}} -> true;
        _ -> false
    end.

teardown_shard(LSock, Mock, Client, Conn) ->
    catch indra_conn:stop(Conn),
    catch gen_tcp:close(Client),
    catch gen_tcp:close(LSock),
    %% MockA/MockB are shared across conns in some tests; stopping an
    %% already-stopped mock is a no-op via catch.
    catch mock_broker:stop(Mock),
    ok.

wait_state(Pid, State) ->
    wait_state(Pid, State, 40).

wait_state(_Pid, _State, 0) ->
    error(state_timeout);
wait_state(Pid, State, Tries) ->
    case sys:get_state(Pid) of
        {State, Data} -> {State, Data};
        _ -> timer:sleep(50), wait_state(Pid, State, Tries - 1)
    end.

recv_exact(Sock, N) ->
    {ok, Bin} = gen_tcp:recv(Sock, N, ?RECV_TIMEOUT),
    Bin.

connect_packet(ClientId, CleanStart, Keepalive) ->
    Flags = case CleanStart of true -> 16#02; false -> 16#00 end,
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.

publish_packet(Topic, PacketId, Flags, Payload) ->
    Var = case (Flags band 16#06) bsr 1 of
        0 -> <<(byte_size(Topic)):16/big, Topic/binary>>;
        _ -> <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big>>
    end,
    Body = <<Var/binary, Payload/binary>>,
    <<3:4, Flags:4, (byte_size(Body)), Body/binary>>.

%% @private Minimal MQTT SUBSCRIBE (remaining length < 128 bytes).
subscribe_packet(PacketId, Filters) ->
    Subs = lists:foldl(
        fun({Filter, QoS}, Acc) ->
            <<Acc/binary, (byte_size(Filter)):16/big, Filter/binary, QoS:8>>
        end, <<>>, Filters),
    Body = <<PacketId:16/big, Subs/binary>>,
    <<16#82, (byte_size(Body)), Body/binary>>.
