%% @doc Chaos verification for restart immunity (Sprint 11).
%%
%% A fake Rust core speaks BrokerLink over loopback. The test drives a
%% full client session through a real listener, conn, brokerlink client
%% and registry, then hard-kills the core (accepted socket dies, listen
%% socket closes), proves the client TCP socket stays open with the conn
%% holding in `await_core`, restarts the core on the same port, and
%% proves seamless rebind (non-clean), silent re-subscription after state
%% loss, buffered-message drain, and resumed messaging — all without a
%% single client disconnect.
-module(indra_chaos_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).
-define(REBIND_BUDGET_MS, 500).

core_restart_zero_disconnect_test() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    {ok, Registry} = indra_conn_registry:start_link(),
    {ok, Broker} = indra_brokerlink:start_link([{transport, tcp},
                                                {host, "127.0.0.1"},
                                                {port, Port},
                                                {reconnect, true},
                                                {backoff_base_ms, 20},
                                                {backoff_max_ms, 100}]),
    {ok, Listener} = indra_listener:start_link([{port, 0},
                                                {conn, [{broker, Broker}]}]),
    Test = self(),
    Core1 = spawn(fun() -> fake_core_accept(LSock, Test) end),
    put(fake_core_pid, Core1),
    try
        {ok, MqttPort} = indra_listener:get_port(Listener),
        {ok, Client} = gen_tcp:connect("127.0.0.1", MqttPort,
                                       [binary, {packet, raw}, {active, false}],
                                       5000),
        try
            %% The conn registers at takeover, before CONNECT arrives.
            [{ConnId, ConnPid}] = wait_members(1),
            %% --- Steady state: full handshake + subscribe + publish.
            ok = gen_tcp:send(Client, connect_packet(<<"chaos-dev">>, true, 60)),
            {core_frame, BindH, BindMeta, _} = next_frame(),
            ?assertEqual(16#0010, maps:get(opcode, BindH)),
            {ok, Bind} = indra_brokerlink:decode_bind_meta(BindMeta),
            ?assertEqual(<<"chaos-dev">>, maps:get(client_id, Bind)),
            core_send(encode_session_binding(ConnId, 1, false, 0)),
            ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>,
                         recv_exact(Client, 4)),
            ok = gen_tcp:send(Client, subscribe_packet(7, [{<<"t">>, 0}])),
            {core_frame, SubH, _SubMeta, _} = next_frame(),
            ?assertEqual(16#0030, maps:get(opcode, SubH)),
            core_send(indra_brokerlink:encode_frame(
                        16#0031, ConnId, 99,
                        indra_brokerlink:encode_suback_meta(7, [0]), <<>>)),
            ?assertEqual(<<16#90, 16#03, 16#00, 16#07, 16#00>>,
                         recv_exact(Client, 5)),
            ok = gen_tcp:send(Client, publish_packet(<<"t">>, 0, 16#30, <<"one">>)),
            {core_frame, PubH, _, PubPay} = next_frame(),
            ?assertEqual(16#0020, maps:get(opcode, PubH)),
            ?assertEqual(<<"one">>, PubPay),
            ?assertMatch({connected, _}, sys:get_state(ConnPid)),

            %% --- Kill the core: accepted socket dies, listen closes.
            ok = gen_tcp:close(LSock),
            exit(Core1, kill),
            %% Connection holds with the client socket OPEN (no EOF).
            ?assertMatch({await_core, _}, wait_state(ConnPid, await_core)),
            ?assertEqual({error, timeout}, gen_tcp:recv(Client, 0, 300)),
            ?assert(is_process_alive(ConnPid)),

            %% --- Outage traffic buffers; PINGREQ still answered.
            ok = gen_tcp:send(Client, publish_packet(<<"t">>, 0, 16#30, <<"held">>)),
            ok = gen_tcp:send(Client, <<16#C0, 16#00>>),
            ?assertEqual(<<16#D0, 16#00>>, recv_exact(Client, 2)),

            %% --- Restart the core on the same port.
            T0 = erlang:monotonic_time(millisecond),
            {ok, LSock2} = relisten(Port, 50),
            put(fake_core_pid, spawn(fun() -> fake_core_accept(LSock2, Test) end)),
            %% Rebind arrives non-clean on a fresh sequence.
            {core_frame, RebindH, RebindMeta, _} = next_frame(),
            ?assertEqual(16#0010, maps:get(opcode, RebindH)),
            ?assertEqual(ConnId, maps:get(conn_id, RebindH)),
            {ok, Rebind} = indra_brokerlink:decode_bind_meta(RebindMeta),
            ?assertEqual(<<"chaos-dev">>, maps:get(client_id, Rebind)),
            ?assertEqual(false, maps:get(clean_start, Rebind)),
            %% Core lost state: present=false triggers silent resubscribe.
            core_send(encode_session_binding(ConnId, 2, false, 0)),
            {core_frame, ResubH, ResubMeta, _} = next_frame(),
            ?assertEqual(16#0030, maps:get(opcode, ResubH)),
            {ok, Resub} = indra_brokerlink:decode_subscribe_meta(ResubMeta),
            ?assertEqual([{<<"t">>, 0}], maps:get(subscriptions, Resub)),
            core_send(indra_brokerlink:encode_frame(
                        16#0031, ConnId, 100,
                        indra_brokerlink:encode_suback_meta(7, [0]), <<>>)),
            ?assertMatch({connected, _}, wait_state(ConnPid, connected)),
            T1 = erlang:monotonic_time(millisecond),
            Elapsed = T1 - T0,
            io:format("core restart recovery took ~p ms~n", [Elapsed]),
            ?assert(Elapsed < ?REBIND_BUDGET_MS),
            %% The held publish drained through the new core...
            {core_frame, HeldH, _, HeldPay} = next_frame(),
            ?assertEqual(16#0020, maps:get(opcode, HeldH)),
            ?assertEqual(<<"held">>, HeldPay),
            %% ...and live messaging resumes end to end.
            ok = gen_tcp:send(Client, publish_packet(<<"t">>, 0, 16#30, <<"two">>)),
            {core_frame, Pub2H, _, Pub2Pay} = next_frame(),
            ?assertEqual(16#0020, maps:get(opcode, Pub2H)),
            ?assertEqual(<<"two">>, Pub2Pay),
            %% Still no duplicate SUBACK and no disconnect, ever.
            ?assertEqual({error, timeout}, gen_tcp:recv(Client, 0, 200)),
            gen_tcp:close(LSock2)
        after
            gen_tcp:close(Client)
        end
    after
        indra_listener:stop(Listener),
        indra_brokerlink:stop(Broker),
        indra_conn_registry:stop(Registry),
        catch gen_tcp:close(LSock)
    end.

%%====================================================================
%% Fake core + helpers
%%====================================================================

%% @private Accept one BrokerLink connection and relay decoded frames to
%% the test; `{core_send, Binary}` from the test goes back on the wire.
%% Dies (with its socket) on `exit(Pid, kill)` to simulate a core crash.
fake_core_accept(LSock, Test) ->
    case gen_tcp:accept(LSock, 5000) of
        {ok, Sock} -> fake_core_loop(Sock, Test, <<>>);
        {error, _} -> ok
    end.

fake_core_loop(Sock, Test, Buf) ->
    receive
        {core_send, Bin} ->
            ok = gen_tcp:send(Sock, Bin),
            fake_core_loop(Sock, Test, Buf)
    after 0 ->
        case gen_tcp:recv(Sock, 0, 100) of
            {ok, Data} ->
                Rest = drain_core_frames(<<Buf/binary, Data/binary>>, Sock, Test),
                fake_core_loop(Sock, Test, Rest);
            {error, timeout} ->
                fake_core_loop(Sock, Test, Buf);
            {error, closed} ->
                Test ! core_peer_closed,
                ok
        end
    end.

drain_core_frames(Buf, Sock, Test) ->
    case indra_brokerlink:decode_frame(Buf) of
        {ok, Header, Meta, Payload, Rest} ->
            Test ! {core_frame, Header, Meta, Payload},
            drain_core_frames(Rest, Sock, Test);
        {more, _} ->
            Buf;
        {error, _} ->
            <<>>
    end.

core_send(Bin) ->
    %% Route the reply to the currently live core handler.
    case get(fake_core_pid) of
        undefined -> error(no_live_core);
        Pid -> Pid ! {core_send, Bin}, ok
    end.

%% @private Next decoded frame from the core, in strict protocol order.
next_frame() ->
    receive
        {core_frame, _Header, _Meta, _Payload} = Frame -> Frame
    after 5000 ->
        error(core_frame_timeout)
    end.

%% @private Wait until exactly one conn is registered (post-takeover).
wait_members(1) ->
    wait_members(1, 60).

wait_members(_N, 0) ->
    error(conn_never_registered);
wait_members(N, Tries) ->
    case indra_conn_registry:members() of
        Members when length(Members) =:= N -> Members;
        _ -> timer:sleep(50), wait_members(N, Tries - 1)
    end.

encode_session_binding(ConnId, Seq, Present, RC) ->
    indra_brokerlink:encode_frame(16#0011, ConnId, Seq,
                                  indra_brokerlink:encode_session_binding_meta(
                                    4242, Present, RC),
                                  <<>>).

recv_exact(Sock, N) ->
    {ok, Bin} = gen_tcp:recv(Sock, N, 2000),
    Bin.

wait_state(Pid, State) ->
    wait_state(Pid, State, 60).

wait_state(_Pid, _State, 0) ->
    error(state_timeout);
wait_state(Pid, State, Tries) ->
    case sys:get_state(Pid) of
        {State, _} -> {State, ok};
        _ -> timer:sleep(50), wait_state(Pid, State, Tries - 1)
    end.

%% @private Re-listen a fixed port, retrying against TIME_WAIT churn.
relisten(_Port, 0) ->
    error(relisten_timeout);
relisten(Port, Tries) ->
    case gen_tcp:listen(Port, [binary, {packet, raw},
                               {active, false}, {reuseaddr, true}]) of
        {ok, LSock} -> {ok, LSock};
        {error, _} -> timer:sleep(100), relisten(Port, Tries - 1)
    end.

connect_packet(ClientId, CleanStart, Keepalive) ->
    Flags = case CleanStart of true -> 16#02; false -> 16#00 end,
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.

subscribe_packet(PacketId, Filters) ->
    Subs = lists:foldl(
        fun({Filter, QoS}, Acc) ->
            <<Acc/binary, (byte_size(Filter)):16/big, Filter/binary, QoS:8>>
        end, <<>>, Filters),
    Body = <<PacketId:16/big, Subs/binary>>,
    <<16#82, (byte_size(Body)), Body/binary>>.

publish_packet(Topic, PacketId, Flags, Payload) ->
    Var = case (Flags band 16#06) bsr 1 of
        0 -> <<(byte_size(Topic)):16/big, Topic/binary>>;
        _ -> <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big>>
    end,
    Body = <<Var/binary, Payload/binary>>,
    <<3:4, Flags:4, (byte_size(Body)), Body/binary>>.
