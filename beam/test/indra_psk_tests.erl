%% @doc EUnit tests for TLS PSK on {@link indra_listener} (B5-05).
%%
%% Real OTP `ssl' handshakes against the real edge listener: a correct
%% PSK identity/key connects and publishes through the broker (the mock
%% kernel plays the role the Rust core plays in every other listener
%% test: it answers the bind the edge sends), while an unknown
%% identity, a wrong key, a kernel refusal and a CONNECT username that
%% does not match the negotiated identity are all refused. A
%% certificate client against the same PSK-enabled listener still
%% connects exactly as before.
-module(indra_psk_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 3000).
-define(PSK_ID, <<"sensor-01">>).
-define(PSK_KEY, <<"0123456789abcdef">>).
-define(PSK_SUITE_NAME, "PSK-AES128-GCM-SHA256").

%% @doc Correct PSK identity/key: handshake succeeds, the bind carries
%% the mapped identity as username, the kernel accepts, and a publish
%% flows through the broker in both directions.
psk_handshake_maps_identity_and_publishes_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = start_psk_listener(Mock, [{?PSK_ID, ?PSK_KEY}], []),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        {ok, Client} = psk_connect(Port, ?PSK_ID, ?PSK_KEY),
        try
            ok = ssl:send(Client, connect_packet(<<"psk-dev">>, ?PSK_ID, <<"pw">>, true, 60)),
            [Sent] = wait_binds(Mock, 1),
            {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Sent)),
            ?assertEqual(<<"psk-dev">>, maps:get(client_id, Bind)),
            ?assertEqual(?PSK_ID, maps:get(username, Bind)),
            ?assertEqual(<<"pw">>, maps:get(password, Bind)),
            Conn = maps:get(from, Sent),
            Binding = indra_brokerlink:encode_session_binding_meta(4242, false, 0),
            ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
            {ok, Connack} = ssl:recv(Client, 4, ?RECV_TIMEOUT),
            ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>, Connack),
            ?assertMatch({connected, _}, sys:get_state(Conn)),
            %% Publish through the broker: the edge forwards PUBLISH_IN
            %% and delivers an injected PUBLISH_OUT back to the client.
            ok = ssl:send(Client, publish_packet(<<"psk/topic">>, 7, 16#32, <<"data">>)),
            PubIn = wait_frame(Mock, Conn, 16#0020),
            {ok, PubMeta} = indra_brokerlink:decode_publish_meta(maps:get(meta, PubIn)),
            ?assertEqual(<<"psk/topic">>, maps:get(topic, PubMeta)),
            ?assertEqual(<<"data">>, maps:get(payload, PubIn)),
            Out = indra_brokerlink:encode_publish_meta(<<"psk/topic">>, 9, 1, false, false),
            ok = indra_conn:broker_frame(
                   Conn, #{opcode => 16#0021}, Out, <<"data">>),
            {ok, Pkt, <<>>} = indra_mqtt_codec:decode_packet(ssl_recv_all(Client)),
            ?assertEqual(publish, maps:get(type_atom, Pkt)),
            {ok, Pub} = indra_mqtt_codec:decode_publish(maps:get(payload, Pkt),
                                                       maps:get(flags, Pkt)),
            ?assertEqual(<<"psk/topic">>, maps:get(topic, Pub)),
            ?assertEqual(<<"data">>, maps:get(payload, Pub))
        after
            ssl:close(Client)
        end
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc Unknown PSK identity: the handshake fails and no bind ever
%% reaches the kernel (fail closed).
psk_unknown_identity_fails_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = start_psk_listener(Mock, [{?PSK_ID, ?PSK_KEY}], []),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        ?assertMatch({error, _}, psk_connect(Port, <<"stranger">>, ?PSK_KEY)),
        timer:sleep(300),
        ?assertEqual([], mock_broker:sent(Mock))
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc Correct identity but wrong key: the Finished verify fails, the
%% handshake fails, and no bind ever reaches the kernel (fail closed).
psk_wrong_key_fails_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = start_psk_listener(Mock, [{?PSK_ID, ?PSK_KEY}], []),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        ?assertMatch({error, _}, psk_connect(Port, ?PSK_ID, <<"wrongwrongwrong!">>)),
        timer:sleep(300),
        ?assertEqual([], mock_broker:sent(Mock))
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc The TLS layer accepts but the kernel refuses the mapped
%% identity: the client gets CONNACK 5 (not authorized) and the
%% connection closes. Authorization still belongs to the kernel.
psk_kernel_refusal_refused_at_connect_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = start_psk_listener(Mock, [{?PSK_ID, ?PSK_KEY}], []),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        {ok, Client} = psk_connect(Port, ?PSK_ID, ?PSK_KEY),
        try
            ok = ssl:send(Client, connect_packet(<<"psk-banned">>, ?PSK_ID, <<"pw">>, true, 60)),
            [Sent] = wait_binds(Mock, 1),
            Conn = maps:get(from, Sent),
            Refused = indra_brokerlink:encode_session_binding_meta(0, false, 16#87),
            ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Refused, <<>>),
            {ok, Connack} = ssl:recv(Client, 4, ?RECV_TIMEOUT),
            ?assertEqual(<<16#20, 16#02, 16#00, 16#05>>, Connack),
            ?assertMatch({error, _}, ssl:recv(Client, 1, ?RECV_TIMEOUT))
        after
            ssl:close(Client)
        end
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc A CONNECT username that matches neither absent nor the
%% negotiated PSK identity: the edge closes with no bind sent (fail
%% closed).
psk_connect_username_mismatch_closes_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = start_psk_listener(Mock, [{?PSK_ID, ?PSK_KEY}], []),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        {ok, Client} = psk_connect(Port, ?PSK_ID, ?PSK_KEY),
        try
            ok = ssl:send(Client, connect_packet(<<"psk-dev">>, <<"someone-else">>, <<"pw">>, true, 60)),
            ?assertMatch({error, _}, ssl:recv(Client, 1, ?RECV_TIMEOUT)),
            timer:sleep(300),
            ?assertEqual([], mock_broker:sent(Mock))
        after
            ssl:close(Client)
        end
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc A core flap mid-handshake re-drives the pending bind with the
%% same mapped PSK identity (not anonymous): the kernel sees the mapped
%% identity on the CONNECT event it already handles.
psk_resend_preserves_mapped_identity_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = start_psk_listener(Mock, [{?PSK_ID, ?PSK_KEY}], []),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        {ok, Client} = psk_connect(Port, ?PSK_ID, ?PSK_KEY),
        try
            ok = ssl:send(Client, connect_packet(<<"psk-dev">>, ?PSK_ID, <<"pw">>, true, 60)),
            [Sent] = wait_binds(Mock, 1),
            Conn = maps:get(from, Sent),
            {ok, Mock2} = mock_broker:start_link(),
            try
                ok = gen_statem:cast(Conn, {broker_up, Mock2}),
                [Rebind] = wait_binds(Mock2, 1),
                {ok, Bind2} = indra_brokerlink:decode_bind_meta(maps:get(meta, Rebind)),
                ?assertEqual(<<"psk-dev">>, maps:get(client_id, Bind2)),
                ?assertEqual(?PSK_ID, maps:get(username, Bind2)),
                ?assertEqual(<<"pw">>, maps:get(password, Bind2)),
                ?assertEqual(false, maps:get(clean_start, Bind2))
            after
                mock_broker:stop(Mock2)
            end
        after
            ssl:close(Client)
        end
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc A certificate client against a PSK-enabled listener still
%% connects exactly as before: no PSK identity is captured and the
%% CONNECT username rides the bind untouched.
psk_cert_client_still_works_test() ->
    {Cert, Key} = test_certs(),
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = start_psk_listener(Mock, [{?PSK_ID, ?PSK_KEY}],
                                        [{certfile, Cert}, {keyfile, Key}]),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        {ok, Client} = ssl:connect("127.0.0.1", Port,
                                   [binary, {packet, raw},
                                    {active, false}, {verify, verify_none}],
                                   5000),
        try
            ok = ssl:send(Client, connect_packet(<<"cert-dev">>, <<"cert-user">>, <<"pw">>, true, 60)),
            [Sent] = wait_binds(Mock, 1),
            {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Sent)),
            ?assertEqual(<<"cert-dev">>, maps:get(client_id, Bind)),
            ?assertEqual(<<"cert-user">>, maps:get(username, Bind)),
            Conn = maps:get(from, Sent),
            Binding = indra_brokerlink:encode_session_binding_meta(4242, false, 0),
            ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
            {ok, Connack} = ssl:recv(Client, 4, ?RECV_TIMEOUT),
            ?assertEqual(<<16#20, 16#02, 16#00, 16#00>>, Connack)
        after
            ssl:close(Client)
        end
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%% @doc Misconfigured PSK sets fail the listener start (fail closed):
%% empty table, short key, bad identity, PSK on plaintext, and a
%% half-configured certificate alongside PSK.
psk_bad_config_rejected_test() ->
    process_flag(trap_exit, true),
    try
        {ok, Mock} = mock_broker:start_link(),
        try
            ?assertMatch({error, _},
                         indra_listener:start_link([{transport, ssl},
                                                    {port, 0},
                                                    {psk_keys, []},
                                                    {conn, [{broker, Mock},
                                                            {transport, ssl}]}])),
            ?assertMatch({error, _},
                         indra_listener:start_link([{transport, ssl},
                                                    {port, 0},
                                                    {psk_keys, [{?PSK_ID, <<"short">>}]},
                                                    {conn, [{broker, Mock},
                                                            {transport, ssl}]}])),
            ?assertMatch({error, _},
                         indra_listener:start_link([{transport, ssl},
                                                    {port, 0},
                                                    {psk_keys, [{<<>>, ?PSK_KEY}]},
                                                    {conn, [{broker, Mock},
                                                            {transport, ssl}]}])),
            ?assertMatch({error, _},
                         indra_listener:start_link([{port, 0},
                                                    {psk_keys, [{?PSK_ID, ?PSK_KEY}]},
                                                    {conn, [{broker, Mock}]}])),
            {Cert, _} = test_certs(),
            ?assertMatch({error, _},
                         indra_listener:start_link([{transport, ssl},
                                                    {port, 0},
                                                    {certfile, Cert},
                                                    {psk_keys, [{?PSK_ID, ?PSK_KEY}]},
                                                    {conn, [{broker, Mock},
                                                            {transport, ssl}]}])),
            receive {'EXIT', _, _} -> ok after 1000 -> ok end
        after
            mock_broker:stop(Mock)
        end
    after
        process_flag(trap_exit, false)
    end.

%%====================================================================
%% Helpers
%%====================================================================

start_psk_listener(Mock, PskKeys, Extra) ->
    ConnOpts = [{broker, Mock}, {transport, ssl}],
    indra_listener:start_link([{transport, ssl},
                               {port, 0},
                               {psk_keys, PskKeys},
                               {conn, ConnOpts} | Extra]).

psk_connect(Port, Identity, Key) ->
    Suite = ssl:str_to_suite(?PSK_SUITE_NAME),
    true = is_map(Suite),
    Lookup = fun(psk, _Hint, _Arg) -> {ok, Key} end,
    IdStr = binary_to_list(Identity),
    ssl:connect("127.0.0.1", Port,
                [binary, {packet, raw},
                 {active, false}, {verify, verify_none},
                 {ciphers, [Suite]}, {versions, ['tlsv1.2']},
                 {psk_identity, IdStr},
                 {user_lookup_fun, {Lookup, undefined}}],
                5000).

wait_binds(_Mock, _N, 0) ->
    error(bind_frame_timeout);
wait_binds(Mock, N, Tries) ->
    Binds = [F || F <- mock_broker:sent(Mock),
                  maps:get(opcode, F) =:= 16#0010],
    case length(Binds) >= N of
        true -> Binds;
        false -> timer:sleep(50), wait_binds(Mock, N, Tries - 1)
    end.

wait_binds(Mock, N) ->
    wait_binds(Mock, N, 40).

%% @private Wait for a frame with Opcode sent by Pid.
wait_frame(Mock, Pid, Opcode) ->
    wait_frame(Mock, Pid, Opcode, 40).

wait_frame(_Mock, _Pid, _Opcode, 0) ->
    error(broker_frame_timeout);
wait_frame(Mock, Pid, Opcode, Tries) ->
    Found = [F || F <- mock_broker:sent(Mock),
                  maps:get(from, F) =:= Pid,
                  maps:get(opcode, F) =:= Opcode],
    case Found of
        [Frame | _] -> Frame;
        [] -> timer:sleep(50), wait_frame(Mock, Pid, Opcode, Tries - 1)
    end.

ssl_recv_all(Sock) ->
    {ok, Bin} = ssl:recv(Sock, 0, ?RECV_TIMEOUT),
    Bin.

connect_packet(ClientId, Username, Password, CleanStart, Keepalive) ->
    Flags = (case CleanStart of true -> 16#02; false -> 16#00 end)
        bor 16#80 bor 16#40,
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary,
                (byte_size(Username)):16/big, Username/binary,
                (byte_size(Password)):16/big, Password/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.

publish_packet(Topic, PacketId, Flags, Payload) ->
    Var = case (Flags band 16#06) bsr 1 of
        0 -> <<(byte_size(Topic)):16/big, Topic/binary>>;
        _ -> <<(byte_size(Topic)):16/big, Topic/binary, PacketId:16/big>>
    end,
    Body = <<Var/binary, Payload/binary>>,
    <<3:4, Flags:4, (byte_size(Body)), Body/binary>>.

%% @private Locate the committed self-signed fixtures. Works whether the
%% suite runs from `beam/' or the repo root.
test_certs() ->
    Candidates = [{"test/certs/cert.pem", "test/certs/key.pem"},
                  {"beam/test/certs/cert.pem", "beam/test/certs/key.pem"}],
    case lists:dropwhile(
           fun({C, K}) ->
               filelib:is_regular(C) =:= false orelse filelib:is_regular(K) =:= false
           end, Candidates) of
        [{C, K} | _] -> {C, K};
        [] -> error({missing_test_certs, Candidates})
    end.
