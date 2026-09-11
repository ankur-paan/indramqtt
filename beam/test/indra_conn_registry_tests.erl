%% @doc EUnit tests for {@link indra_conn_registry}.
-module(indra_conn_registry_tests).

-include_lib("eunit/include/eunit.hrl").

register_lookup_unregister_test() ->
    {ok, Reg} = indra_conn_registry:start_link(),
    try
        ?assertEqual({error, not_found}, indra_conn_registry:lookup(7001)),
        ?assertEqual(ok, indra_conn_registry:register(7001, self())),
        ?assertEqual({ok, self()}, indra_conn_registry:lookup(7001)),
        %% Re-registering overwrites the owner.
        Other = spawn(fun() -> timer:sleep(5000) end),
        ?assertEqual(ok, indra_conn_registry:register(7001, Other)),
        ?assertEqual({ok, Other}, indra_conn_registry:lookup(7001)),
        exit(Other, kill),
        ?assertEqual(ok, indra_conn_registry:unregister(7001)),
        ?assertEqual({error, not_found}, indra_conn_registry:lookup(7001)),
        %% Unregistering a missing id is a no-op.
        ?assertEqual(ok, indra_conn_registry:unregister(7001))
    after
        indra_conn_registry:stop(Reg)
    end.

dead_owner_reaped_test() ->
    {ok, Reg} = indra_conn_registry:start_link(),
    try
        Owner = spawn(fun() -> receive stop -> ok end end),
        ?assertEqual(ok, indra_conn_registry:register(7002, Owner)),
        ?assertEqual({ok, Owner}, indra_conn_registry:lookup(7002)),
        Ref = monitor(process, Owner),
        Owner ! stop,
        receive {'DOWN', Ref, process, Owner, _} -> ok
        after 2000 -> error(owner_did_not_stop)
        end,
        %% The DOWN reaper removes the row without an explicit unregister.
        ?assertEqual({error, not_found}, wait_gone(7002, 40))
    after
        indra_conn_registry:stop(Reg)
    end.

safe_without_table_test() ->
    %% No registry running: every call degrades gracefully.
    ?assertEqual({error, not_found}, indra_conn_registry:lookup(7003)),
    ?assertEqual(ok, indra_conn_registry:register(7003, self())),
    ?assertEqual(ok, indra_conn_registry:unregister(7003)),
    ?assertEqual([], indra_conn_registry:members()),
    ?assertEqual(ok, indra_conn_registry:notify_all({broker_down})).

members_lists_everything_test() ->
    {ok, Reg} = indra_conn_registry:start_link(),
    try
        ?assertEqual([], indra_conn_registry:members()),
        Other = spawn(fun() -> timer:sleep(5000) end),
        ?assertEqual(ok, indra_conn_registry:register(7004, self())),
        ?assertEqual(ok, indra_conn_registry:register(7005, Other)),
        Members = lists:sort(indra_conn_registry:members()),
        ?assertEqual([{7004, self()}, {7005, Other}], Members),
        exit(Other, kill)
    after
        indra_conn_registry:stop(Reg)
    end.

notify_all_reaches_members_test() ->
    {ok, Reg} = indra_conn_registry:start_link(),
    try
        ?assertEqual(ok, indra_conn_registry:register(7006, self())),
        ?assertEqual(ok, indra_conn_registry:notify_all({broker_down})),
        receive
            {'$gen_cast', {broker_down}} -> ok
        after 2000 ->
            error(notify_timeout)
        end
    after
        indra_conn_registry:stop(Reg)
    end.

wait_gone(_ConnId, 0) ->
    error(reaper_timeout);
wait_gone(ConnId, Tries) ->
    case indra_conn_registry:lookup(ConnId) of
        {error, not_found} -> {error, not_found};
        {ok, _} -> timer:sleep(50), wait_gone(ConnId, Tries - 1)
    end.
