%% @doc EUnit coverage for egress stages 0-1: attribution that survives
%% the process (stop causes, count-on-close) and the drain path
%% (batched iolist writes, counted-active sockets, Q3 accounting
%% symmetry).
%%
%% Fails before the stages: no stop-cause counters exist, deaths are
%% unattributed, and every PublishOut costs its own socket send with a
%% per-message re-arm. Live-socket tests are self-terminating (every
%% socket closed, every process stopped); counter assertions use
%% before/after deltas so repeated runs stay exact.
-module(indra_egress_stage_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).
-define(PUBLISH_OUT, 16#0021).

%%====================================================================
%% Pure attribution mapping
%%====================================================================

%% @doc Every known stop cause maps to its own aggregate counter, and
%% anything unrecorded stays visible under `unknown' instead of
%% vanishing into a shared bucket.
stop_counter_maps_every_known_cause_test() ->
    Causes = [connect_timeout, keepalive_timeout, peer_closed, tcp_error,
              protocol_error, send_failed, ingress_overloaded, call_timeout,
              call_failed, hold_overflow, kernel_close, client_disconnect],
    Counters = [indra_edge_counters:stop_counter(C) || C <- Causes],
    ?assertEqual(length(Causes), length(lists:usort(Counters))),
    lists:foreach(
      fun(Counter) ->
          ?assertMatch("edge_stop_" ++ _, atom_to_list(Counter))
      end, Counters),
    ?assertEqual(edge_stop_unknown_total,
                 indra_edge_counters:stop_counter(something_unrecorded)).

%% @doc Counter increments are visible through get and snapshot under
%% an isolated probe name.
counters_increment_and_snapshot_test() ->
    Probe = egress_stage_test_probe_total,
    Before = indra_edge_counters:get(Probe),
    indra_edge_counters:inc(Probe),
    indra_edge_counters:inc(Probe, 4),
    ?assertEqual(Before + 5, indra_edge_counters:get(Probe)),
    ?assertEqual(Before + 5, proplists:get_value(Probe, indra_edge_counters:snapshot())).

%% @doc The pending-bytes gauge keeps the largest sample seen, never a
%% sum, regardless of sample order.
passive_gauge_keeps_maximum_test() ->
    MaxBefore = indra_edge_counters:get(edge_send_pending_bytes_max),
    High = MaxBefore + 50,
    ok = indra_edge_counters:note_passive(High),
    ok = indra_edge_counters:note_passive(MaxBefore + 10),
    ?assertEqual(High, indra_edge_counters:get(edge_send_pending_bytes_max)).

%% @doc Flow-control snapshots round-trip; anything but 8 bytes is
%% malformed (and must be ignored by the receiver, never fatal).
credit_meta_codec_round_trip_test() ->
    Meta = indra_brokerlink:encode_credit_meta(7, 1024),
    ?assertEqual({ok, #{used_frames => 7, used_bytes => 1024}},
                 indra_brokerlink:decode_credit_meta(Meta)),
    ?assertEqual(16#0042, indra_brokerlink:opcode_to_int(credit)),
    ?assertEqual(credit, indra_brokerlink:int_to_opcode(16#0042)),
    ?assertMatch({error, _}, indra_brokerlink:decode_credit_meta(<<"short">>)),
    ?assertMatch({error, _}, indra_brokerlink:decode_credit_meta(<<>>)).

%% @doc The close drain labels queued PublishOut frames by QoS, skips
%% control frames, and ignores undecodable remainders without crashing.
close_drain_labels_by_qos_test() ->
    Qos0Meta = indra_brokerlink:encode_publish_meta(<<"t">>, 0, 0, false, false),
    Qos1Meta = indra_brokerlink:encode_publish_meta(<<"t">>, 9, 1, false, false),
    SubackMeta = indra_brokerlink:encode_suback_meta(3, [0]),
    self() ! {'$gen_cast', {broker_frame, #{opcode => ?PUBLISH_OUT}, Qos0Meta, <<"a">>}},
    self() ! {'$gen_cast', {broker_frame, #{opcode => 16#0031}, SubackMeta, <<>>}},
    self() ! {'$gen_cast', {broker_frame, #{opcode => ?PUBLISH_OUT}, Qos1Meta, <<"b">>}},
    self() ! {'$gen_cast', {broker_frame, #{opcode => ?PUBLISH_OUT}, <<"junk">>, <<"c">>}},
    self() ! {'$gen_cast', {broker_frame, #{opcode => ?PUBLISH_OUT}, Qos0Meta, <<"d">>}},
    self() ! {not_a_cast, hello},
    ?assertEqual({2, 1}, indra_conn:drain_close_discards()),
    %% Nothing matching is left behind; the stranger never matched.
    ?assertEqual({0, 0}, indra_conn:drain_close_discards()),
    receive {not_a_cast, hello} -> ok after 0 -> error(stranger_consumed) end.

%%====================================================================
%% Stop-cause attribution over live connections
%%====================================================================

%% @doc A non-CONNECT first packet still closes the connection -- and
%% now the death is attributed: exactly one `protocol_error' stop.
protocol_violation_counts_stop_cause_test() ->
    Before = indra_edge_counters:get(edge_stop_protocol_error_total),
    {LSock, _Port, Mock, Client, Conn} = setup([{conn_id, 910101}]),
    Ref = monitor(process, Conn),
    try
        ok = gen_tcp:send(Client, <<16#C0, 16#00>>),
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT)),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(conn_did_not_die)
        end,
        ?assertEqual(Before + 1,
                     indra_edge_counters:get(edge_stop_protocol_error_total))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

%% @doc A client DISCONNECT closes with cause `client_disconnect',
%% counted once; the kernel unbind still goes out first.
client_disconnect_counts_stop_cause_test() ->
    Before = indra_edge_counters:get(edge_stop_client_disconnect_total),
    {LSock, _Port, Mock, Client, Conn} = setup([{conn_id, 910102}]),
    Ref = monitor(process, Conn),
    try
        handshake(Client, Mock, <<"stage-disc">>, Conn),
        ok = gen_tcp:send(Client, <<16#E0, 16#00>>),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after ?RECV_TIMEOUT -> error(conn_did_not_die)
        end,
        [Bind, Unbind] = wait_frames(Mock, 2),
        ?assertEqual(16#0010, maps:get(opcode, Bind)),
        ?assertEqual(16#0012, maps:get(opcode, Unbind)),
        ?assertEqual(Before + 1,
                     indra_edge_counters:get(edge_stop_client_disconnect_total))
    after
        teardown(LSock, Mock, Client, Conn)
    end.

%%====================================================================
%% Drain path: batching, order, accounting symmetry
%%====================================================================

%% @doc The socket runs counted-active instead of re-arming per
%% message, keeping nodelay and the 64 KiB buffer bounds.
counted_active_sockopts_test() ->
    Opts = indra_conn:conn_sock_opts(),
    ?assertMatch({active, _}, lists:keyfind(active, 1, Opts)),
    {active, N} = lists:keyfind(active, 1, Opts),
    ?assert(is_integer(N) andalso N > 1),
    ?assert(lists:member({nodelay, true}, Opts)),
    ?assert(lists:member({recbuf, 65536}, Opts)),
    ?assert(lists:member({sndbuf, 65536}, Opts)).

%% @doc Three PublishOut frames queued together arrive as one ordered
%% byte stream (single batched write): same bytes as three lone sends,
%% arrival order preserved, credit account back to zero, and no
%% flow-control chatter on a healthy path.
batched_publish_out_arrives_in_order_test() ->
    ConnId = 910103,
    {LSock, _Port, Mock, Client, Conn} = setup([{conn_id, ConnId}]),
    try
        handshake(Client, Mock, <<"stage-batch">>, Conn),
        Frames = [make_publish_out(N) || N <- [1, 2, 3]],
        Expected = iolist_to_binary([Packet || {_H, _M, _P, Packet} <- Frames]),
        %% Admit through the same body measure dispatch uses, so the
        %% release on send must return the account to exactly zero.
        lists:foreach(
          fun({H, M, P, _Packet}) ->
              Size = byte_size(M) + byte_size(P),
              ?assertMatch({admit, _},
                           indra_edge_counters:egress_admit(ConnId, 0, Size)),
              ok = indra_conn:broker_frame(Conn, H, M, P)
          end, Frames),
        Got = recv_bytes(Client, byte_size(Expected)),
        ?assertEqual(Expected, Got),
        ?assertEqual({ok, {0, 0, false}},
                     indra_edge_counters:credit_snapshot(ConnId)),
        ?assertEqual([], [F || F <- mock_broker:sent(Mock),
                               maps:get(opcode, F) =:= credit])
    after
        teardown(LSock, Mock, Client, Conn)
    end.

%%====================================================================
%% Helpers
%%====================================================================

setup(ConnOpts) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    {ok, Mock} = mock_broker:start_link(),
    Parent = self(),
    spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Conn} = indra_conn:start_link(Sock, [{broker, Mock} | ConnOpts]),
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
    {LSock, Port, Mock, Client, Conn}.

teardown(LSock, Mock, Client, Conn) ->
    catch indra_conn:stop(Conn),
    catch gen_tcp:close(Client),
    catch gen_tcp:close(LSock),
    catch mock_broker:stop(Mock),
    catch indra_edge_counters:credit_delete(910103),
    ok.

wait_frames(Mock, N) ->
    wait_frames(Mock, N, 40).

wait_frames(_Mock, _N, 0) ->
    error(broker_frame_timeout);
wait_frames(Mock, N, Tries) ->
    case mock_broker:sent(Mock) of
        Frames when length(Frames) >= N -> Frames;
        _ -> timer:sleep(50), wait_frames(Mock, N, Tries - 1)
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

handshake(Client, Mock, ClientId, Conn) ->
    ok = gen_tcp:send(Client, connect_packet(ClientId, true, 60)),
    [_Bind] = wait_frames(Mock, 1),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = recv_exact(Client, 4),
    ok.

%% @private One QoS 0 PublishOut frame plus its expected wire bytes.
make_publish_out(N) ->
    Topic = <<"stage/t">>,
    Payload = <<"payload-", N>>,
    Meta = indra_brokerlink:encode_publish_meta(Topic, 0, 0, false, false),
    Header = #{opcode => ?PUBLISH_OUT},
    Packet = indra_mqtt_codec:encode_publish(Topic, 0, 0, false, false, Payload),
    {Header, Meta, Payload, Packet}.

%% @private Receive exactly N bytes (TCP may segment the batch).
recv_bytes(_Sock, 0) ->
    <<>>;
recv_bytes(Sock, N) ->
    {ok, Bin} = gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT),
    Got = byte_size(Bin),
    case Got >= N of
        true ->
            <<Wanted:N/binary, _/binary>> = Bin,
            Wanted;
        false ->
            Rest = recv_bytes(Sock, N - Got),
            <<Bin/binary, Rest/binary>>
    end.
