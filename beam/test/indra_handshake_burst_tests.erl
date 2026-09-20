%% @doc Handshake-burst diagnosis: why simultaneous subscribes miss SUBACK.
%%
%% Under a burst of simultaneous subscribes, some clients never observe
%% their SUBACK inside the barrier window, while staggered connects are
%% clean. These tests pin the mechanism on the edge side with evidence
%% distinguishing the three candidates:
%% <ul>
%% <li>shed before request: the shared shard server is past its
%% ingress bound, so {@code indra_brokerlink:send/6} answers
%% {@code {error, overloaded}} and the connection stops before any
%% SubscribeIn is emitted;</li>
%% <li>call-timeout kill: the shard server is slow (backlog), the 5 s
%% {@code gen_server:call} times out, and the connection stops after
%% requesting but before the SubAck arrives;</li>
%% <li>staggered control: the same 200 subscribes spaced out all answer.
%% </li>
%% </ul>
%%
%% All tests are self-terminating: every socket is closed and every
%% process stopped within the test. No daemons, no external services —
%% the kernel is replaced by a controllable in-test shard server with
%% the same call protocol the edge uses against {@code indra_brokerlink}.
-module(indra_handshake_burst_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).
-define(BURST_N, 200).
-define(BURST_BARRIER_MS, 20000).
-define(CALL_TIMEOUT_MS, 5000).

%%====================================================================
%% Candidate 1: shed before request kills the subscribe handshake
%%====================================================================

%% @doc A SUBSCRIBE arriving while the shared shard is past its ingress
%% bound never reaches the kernel: send/6 sheds it, the connection
%% stops, the client socket closes with no SUBACK bytes, and the shard
%% recorded no SubscribeIn for the connection.
subscribe_overload_sheds_before_request_test_() ->
    {timeout, 30, fun() ->
    {LSock, Slow, Client, Conn} = setup_slow(9101),
    Ref = monitor(process, Conn),
    try
        handshake_slow(Client, Slow, <<"burst-shed">>, Conn, 9101),
        %% Saturate the shard past the send/6 bound with raw fillers.
        slow_set_delay(Slow, 400),
        [spawn(fun() ->
                   catch gen_server:call(Slow, {send, 16#0001, 1, 1, <<>>, <<"f">>},
                                         infinity)
               end) || _ <- lists:seq(1, 400)],
        ok = wait_queue_full(Slow, 256, 100),
        ok = gen_tcp:send(Client, subscribe_packet(7, [{<<"burst/shed">>, 1}])),
        %% No SUBACK: the socket just closes.
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT)),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(conn_did_not_stop)
        end,
        %% Shed, not dropped downstream: the kernel never saw SubscribeIn.
        Subs = [F || F <- slow_sent(Slow), maps:get(opcode, F) =:= 16#0030],
        ?assertEqual([], Subs)
    after
        teardown_slow(LSock, Slow, Client, Conn),
        demonitor(Ref, [flush])
    end end}.

%%====================================================================
%% Candidate 2: the 5 s call timeout kills the subscribe handshake
%%====================================================================

%% @doc A SUBSCRIBE whose shard reply arrives after the 5 s call
%% timeout stops the connection: the client socket closes with no
%% SUBACK, even though the kernel (slow here) did record the request.
subscribe_call_timeout_kills_connection_test_() ->
    {timeout, 30, fun() ->
    {LSock, Slow, Client, Conn} = setup_slow(9102),
    Ref = monitor(process, Conn),
    try
        handshake_slow(Client, Slow, <<"burst-timeout">>, Conn, 9102),
        %% Every shard reply now lands after the 5 s call timeout.
        slow_set_delay(Slow, ?CALL_TIMEOUT_MS + 1000),
        ok = gen_tcp:send(Client, subscribe_packet(7, [{<<"burst/timeout">>, 1}])),
        ?assertEqual({error, closed},
                     gen_tcp:recv(Client, 0, ?CALL_TIMEOUT_MS + 3000)),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(conn_did_not_stop)
        end,
        %% Requested but answered too late: exactly one SubscribeIn.
        Subs = [F || F <- slow_sent(Slow), maps:get(opcode, F) =:= 16#0030],
        ?assertEqual(1, length(Subs))
    after
        slow_set_delay(Slow, 0),
        teardown_slow(LSock, Slow, Client, Conn),
        demonitor(Ref, [flush])
    end end}.

%%====================================================================
%% Burst shape: 200 simultaneous subscribes lose SUBACKs (timeout kills)
%%====================================================================

%% @doc 200 simultaneous subscribes through one shared shard lose
%% SUBACKs: every request is served slower than the 5 s call timeout
%% past queue position ~100, so late connections die before their
%% SubAck arrives. Every miss maps to a dead connection, and the shard
%% recorded all 200 SubscribeIn frames (nothing was shed: the queue
%% stays below the ingress bound).
burst_200_subscribes_lose_subacks_test_() ->
    {timeout, 120, fun() ->
    N = ?BURST_N,
    {LSock, Acc, Slow, Conns, Clients} = setup_burst(N, 9100, 0),
    try
        %% Serve one frame per 50 ms: the drain takes ~10 s, so every
        %% request past position ~100 still waits past the 5 s timeout.
        slow_set_delay(Slow, 50),
        _ = spawn_responder(Slow),
        %% Simultaneous burst: all subscribes on the wire within ms.
        [ok = gen_tcp:send(C, subscribe_packet(7, [{<<"burst/all">>, 1}]))
         || C <- Clients],
        Results = collect_results(Clients, ?BURST_BARRIER_MS),
        Ready = length([R || R <- Results, R =:= ready]),
        Misses = N - Ready,
        ?assert(Misses >= 1),
        %% Nothing shed: all 200 subscribes reached the shard.
        ok = wait_sub_count(Slow, N, 300),
        %% Every miss is a killed connection, not a late SUBACK.
        Dead = length([P || P <- Conns, not is_process_alive(P)]),
        ?assert(Dead >= Misses),
        io:format(user, "~nburst: ~p/~p SUBACKs, ~p misses, ~p conns dead~n",
                  [Ready, N, Misses, Dead])
    after
        teardown_burst(LSock, Acc, Slow, Conns, Clients)
    end end}.

%%====================================================================
%% Control: the same 200 subscribes staggered are all clean
%%====================================================================

%% @doc Control for the burst: the same 200 subscribes spaced 5 ms
%% apart through one shared shard all answer inside the barrier and
%% every connection stays up.
staggered_200_subscribes_all_answered_test_() ->
    {timeout, 120, fun() ->
    N = ?BURST_N,
    {LSock, Acc, Slow, Conns, Clients} = setup_burst(N, 9300, 0),
    try
        _ = spawn_responder(Slow),
        [begin
             ok = gen_tcp:send(C, subscribe_packet(7, [{<<"burst/calm">>, 1}])),
             timer:sleep(5)
         end || C <- Clients],
        Results = collect_results(Clients, ?BURST_BARRIER_MS),
        Ready = length([R || R <- Results, R =:= ready]),
        ?assertEqual(N, Ready),
        Alive = length([P || P <- Conns, is_process_alive(P)]),
        ?assertEqual(N, Alive)
    after
        teardown_burst(LSock, Acc, Slow, Conns, Clients)
    end end}.

%%====================================================================
%% Shared controllable shard (same call protocol as indra_brokerlink)
%%====================================================================

%% @private Start the burst stack: one shared slow shard, a listener,
%% an acceptor, and N handshaked connections with clients. Delay is the
%% per-frame service time in ms.
setup_burst(N, ConnBase, Delay) ->
    Slow = spawn(fun() -> burst_loop(Delay, []) end),
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Parent = self(),
    Acc = spawn(fun() -> accept_loop(LSock, Slow, ConnBase, Parent) end),
    Pairs = [begin
                 {ok, Client} = gen_tcp:connect("127.0.0.1", Port,
                                               [binary, {packet, raw},
                                                {active, false}], 5000),
                 {Conn, ConnId} = receive {conn_ready, C, Id} -> {C, Id}
                                  after 5000 -> error(conn_not_ready)
                                  end,
                 ClientId = <<"burst-", (integer_to_binary(I))/binary>>,
                 ok = handshake_client(Client, Conn, Slow, ClientId, ConnId),
                 {Conn, Client}
             end || I <- lists:seq(1, N)],
    Conns = [Conn || {Conn, _} <- Pairs],
    Clients = [Client || {_, Client} <- Pairs],
    [monitor(process, P) || P <- Conns],
    {LSock, Acc, Slow, Conns, Clients}.

teardown_burst(LSock, Acc, Slow, Conns, Clients) ->
    [catch indra_conn:stop(P) || P <- Conns],
    [catch gen_tcp:close(C) || C <- Clients],
    catch gen_tcp:close(LSock),
    catch exit(Acc, kill),
    catch exit(Slow, kill),
    ok.

%% @private Accept loop: every connection pins the ONE shared shard,
%% exactly like a single-shard edge under burst.
accept_loop(LSock, Slow, Base, Parent) ->
    accept_loop(LSock, Slow, Base, Parent, 0).

accept_loop(LSock, Slow, Base, Parent, K) ->
    case gen_tcp:accept(LSock, 10000) of
        {ok, Sock} ->
            case indra_conn:start_link(Sock, [{broker, Slow},
                                              {conn_id, Base + K}]) of
                {ok, Conn} ->
                    ok = gen_tcp:controlling_process(Sock, Conn),
                    gen_statem:cast(Conn, takeover),
                    Parent ! {conn_ready, Conn, Base + K},
                    accept_loop(LSock, Slow, Base, Parent, K + 1);
                {error, _} ->
                    catch gen_tcp:close(Sock),
                    accept_loop(LSock, Slow, Base, Parent, K)
            end;
        {error, _} ->
            ok
    end.

%% @private CONNECT -> CONNACK against the shared shard. Waits for this
%% connection's own bind to be recorded before delivering the binding,
%% so the handshake never races the request.
handshake_client(Client, Conn, Slow, ClientId, ConnId) ->
    ok = gen_tcp:send(Client, connect_packet(ClientId, true, 60)),
    ok = wait_conn_frame(Slow, ConnId, 100),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = recv_exact(Client, 4),
    ok.

%% @private One waiter per client: reports ready on SUBACK bytes,
%% miss on close/timeout. Concurrent so one slow socket cannot hold
%% the barrier for the rest.
collect_results(Clients, Barrier) ->
    Parent = self(),
    [spawn(fun() ->
               Res = case gen_tcp:recv(C, 5, Barrier) of
                         {ok, <<16#90, _, _, _, _>>} -> ready;
                         _ -> miss
                     end,
               Parent ! {sub_result, Res}
           end) || C <- Clients],
    gather(length(Clients), []).

gather(0, Acc) ->
    Acc;
gather(N, Acc) ->
    receive
        {sub_result, R} -> gather(N - 1, [R | Acc])
    after ?BURST_BARRIER_MS + 10000 -> error(result_barrier_timeout)
    end.

%% @private Responder: feeds every recorded SubscribeIn back as a
%% granted SubAckOut, so any connection still alive always answers.
%% Exits with the shard.
spawn_responder(Slow) ->
    spawn(fun() -> responder_loop(Slow, sets:new()) end).

responder_loop(Slow, Seen) ->
    case is_process_alive(Slow) of
        false -> ok;
        true ->
            receive
                stop -> ok
            after 0 ->
                Frames = case catch gen_server:call(Slow, get_frames, 5000) of
                             L when is_list(L) -> L;
                             _ -> []
                         end,
                Seen1 = lists:foldl(fun answer_new/2, Seen, Frames),
                timer:sleep(25),
                responder_loop(Slow, Seen1)
            end
    end.

answer_new(F, Acc) ->
    case maps:get(opcode, F, undefined) of
        16#0030 ->
            Key = {maps:get(conn_id, F), maps:get(seq_no, F)},
            case sets:is_element(Key, Acc) of
                true -> Acc;
                false ->
                    answer_sub(F),
                    sets:add_element(Key, Acc)
            end;
        _ -> Acc
    end.

answer_sub(F) ->
    From = maps:get(from, F),
    {ok, Meta} = indra_brokerlink:decode_subscribe_meta(maps:get(meta, F)),
    Ack = indra_brokerlink:encode_suback_meta(maps:get(packet_id, Meta), [0]),
    catch indra_conn:broker_frame(From, #{opcode => 16#0031}, Ack, <<>>),
    ok.

%% @private Slow shared shard: sleeps Delay ms per {send, ...} call
%% and records the caller for the responder. Control messages win via
%% selective receive so they work while hundreds of sends queue.
burst_loop(Delay, Frames) ->
    receive
        {set_delay, Ms} ->
            burst_loop(Ms, Frames);
        {'$gen_call', From, get_frames} ->
            gen_server:reply(From, lists:reverse(Frames)),
            burst_loop(Delay, Frames)
    after 0 ->
        receive
            {set_delay, Ms} ->
                burst_loop(Ms, Frames);
            {'$gen_call', From, get_frames} ->
                gen_server:reply(From, lists:reverse(Frames)),
                burst_loop(Delay, Frames);
            {'$gen_call', From, {send, Opcode, ConnId, SeqNo, Meta, Payload}} ->
                timer:sleep(Delay),
                gen_server:reply(From, ok),
                burst_loop(Delay, [#{from => element(1, From), opcode => Opcode,
                                     conn_id => ConnId, seq_no => SeqNo,
                                     meta => Meta, payload => Payload} | Frames]);
            stop ->
                ok
        end
    end.

slow_sent(Slow) ->
    gen_server:call(Slow, get_frames, 5000).

slow_set_delay(Slow, Ms) ->
    Slow ! {set_delay, Ms},
    ok.

wait_conn_frame(_Slow, _ConnId, 0) ->
    error(slow_frame_timeout);
wait_conn_frame(Slow, ConnId, Tries) ->
    Match = [F || F <- slow_sent(Slow), maps:get(conn_id, F) =:= ConnId],
    case Match of
        [_ | _] -> ok;
        [] -> timer:sleep(50), wait_conn_frame(Slow, ConnId, Tries - 1)
    end.

wait_sub_count(_Slow, _N, 0) ->
    error(slow_sub_timeout);
wait_sub_count(Slow, N, Tries) ->
    Subs = [F || F <- slow_sent(Slow), maps:get(opcode, F) =:= 16#0030],
    case length(Subs) >= N of
        true -> ok;
        false -> timer:sleep(50), wait_sub_count(Slow, N, Tries - 1)
    end.

wait_queue_full(_Slow, _Bound, 0) ->
    error(queue_never_filled);
wait_queue_full(Slow, Bound, Tries) ->
    case process_info(Slow, message_queue_len) of
        {message_queue_len, N} when N >= Bound -> ok;
        _ -> timer:sleep(50), wait_queue_full(Slow, Bound, Tries - 1)
    end.

%%====================================================================
%% Single-connection slow-broker harness (shed/timeout candidates)
%%====================================================================

setup_slow(ConnId) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Slow = spawn(fun() -> burst_loop(0, []) end),
    Parent = self(),
    spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Conn} = indra_conn:start_link(Sock, [{broker, Slow},
                                                 {conn_id, ConnId}]),
        ok = gen_tcp:controlling_process(Sock, Conn),
        gen_statem:cast(Conn, takeover),
        Parent ! {conn_ready, Conn, ConnId}
    end),
    {ok, Client} = gen_tcp:connect("127.0.0.1", Port,
                                   [binary, {packet, raw}, {active, false}],
                                   5000),
    Conn = receive {conn_ready, C, _Id} -> C
           after 5000 -> error(conn_not_ready)
           end,
    {LSock, Slow, Client, Conn}.

teardown_slow(LSock, Slow, Client, Conn) ->
    catch indra_conn:stop(Conn),
    catch gen_tcp:close(Client),
    catch gen_tcp:close(LSock),
    catch exit(Slow, kill),
    ok.

handshake_slow(Client, Slow, ClientId, Conn, ConnId) ->
    ok = gen_tcp:send(Client, connect_packet(ClientId, true, 60)),
    ok = wait_conn_frame(Slow, ConnId, 100),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = recv_exact(Client, 4),
    ok.

%%====================================================================
%% Minimal MQTT 3.1.1 packets
%%====================================================================

recv_exact(Sock, N) ->
    {ok, Bin} = gen_tcp:recv(Sock, N, ?RECV_TIMEOUT),
    Bin.

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
