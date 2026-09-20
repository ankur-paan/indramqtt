%% @doc Edge attribution + egress credit accounts (egress stages 0-1).
%%
%% Two ETS tables, both created (and owned) by {@link
%% indra_conn_registry} so they survive any single connection death and
%% die with the edge:
%% <ul>
%% <li>{@code indra_edge_counters}: {@code {Counter, Value}} aggregates.
%% Every increment names the event; no counter is ever decremented or
%% reset except by node restart. Read them with {@link snapshot/0} (the
%% scrape path for load runs) rather than {@code sys:get_state}.</li>
%% <li>{@code indra_egress_credit}: {@code {ConnId, UsedFrames,
%% UsedBytes, Slowed}} per-connection egress accounts backing the Q3
%% dispatch bound. `Used' counts BrokerLink PublishOut body bytes
%% (meta + payload) admitted but not yet written to the client socket;
%% both sides of the accounting use that same measure so the two
%% counters cannot drift apart by encoding.</li>
%% </ul>
%%
%% Counter inventory (all `update_counter'-only writes):
%% <ul>
%% <li>Stop causes, one per {@code terminate/3}: {@code
%% edge_stop_connect_timeout_total}, {@code edge_stop_keepalive_timeout_total},
%% {@code edge_stop_peer_closed_total}, {@code edge_stop_tcp_error_total},
%% {@code edge_stop_protocol_error_total}, {@code edge_stop_send_failed_total},
%% {@code edge_stop_ingress_overloaded_total} (a QoS 1+ ingress kill on an
%% overloaded shard call; the stall-instead-of-kill redesign removes the
%% kill and this counter with it), {@code edge_stop_call_timeout_total},
%% {@code edge_stop_call_failed_total}, {@code edge_stop_hold_overflow_total},
%% {@code edge_stop_kernel_close_total}, {@code
%% edge_stop_client_disconnect_total}, {@code edge_stop_unknown_total}
%% (a death with no recorded cause: a bug, kept visible).</li>
%% <li>Soft throttle events: {@code edge_slowed_total} / {@code
%% edge_recovered_total} (Q3 bound crossings, hysteresis-guarded).</li>
%% <li>Shed points: {@code edge_dispatch_qos0_shed_total} (QoS 0 refused
%% at dispatch past the Q3 cap), {@code edge_ingress_qos0_shed_total}
%% (mirror of the per-connection PERF-09 ingress shed), {@code
%% edge_egress_send_failed_total} (mirror of the per-connection PERF-10
%% send-failure drops), {@code edge_egress_qos1_over_cap_total} (QoS 1
%% admitted past the Q3 cap because no deferral exists yet: never shed,
%% always counted).</li>
%% <li>Count-on-close: {@code edge_egress_discarded_at_close_qos0_total} /
%% {@code _qos1_total} (queued PublishOut frames evaporating with a dying
%% connection, labelled by QoS), {@code
%% edge_puback_unacked_at_close_total} (QoS 1 publishes accepted from the
%% socket but never PUBACKed).</li>
%% <li>Gauge: {@code edge_send_pending_bytes_max} (largest client-socket
%% mailbox sample seen at a passive re-arm; a maximum, never a sum).</li>
%% </ul>
%%
%% Q3 bound rationale, stated so a reviewer can redo the arithmetic: 128
%% frames x ~200 B/frame (128 B payload + headers) ~= 26 KiB per
%% connection, plus the 64 KiB socket cap ~= ~90 KiB worst case per
%% connection; 500 subscribers ~= ~45 MB worst case, typically far less.
%% The 64 KiB byte leg mirrors the existing socket send-buffer cap, so it
%% adds no new tuning knob. Re-admission below half cap (64 frames /
%% 32 KiB) gives the hysteresis against flap.
-module(indra_edge_counters).

-export([ensure/0,
         inc/1,
         inc/2,
         get/1,
         snapshot/0,
         stop_counter/1,
         egress_admit/3,
         egress_released/3,
         credit_snapshot/1,
         credit_delete/1,
         note_passive/1,
         cap_frames/0,
         cap_bytes/0]).

-define(COUNTERS, indra_edge_counters).
-define(CREDIT, indra_egress_credit).

%% Q3 per-connection egress bound (dual: frames AND bytes, whichever
%% trips first). Re-admit below half cap (hysteresis against flap).
-define(CAP_FRAMES, 128).
-define(CAP_BYTES, 65536).
-define(LOW_FRAMES, 64).
-define(LOW_BYTES, 32768).

%% @doc Q3 frame cap (see the bound rationale above).
-spec cap_frames() -> pos_integer().
cap_frames() -> ?CAP_FRAMES.

%% @doc Q3 byte cap (mirrors the socket send-buffer cap).
-spec cap_bytes() -> pos_integer().
cap_bytes() -> ?CAP_BYTES.

%% @doc Create both tables when absent. Idempotent and cheap (two
%% `whereis' checks): every API entry calls it first so the module stays
%% total when the registry is absent (unit tests, standalone shards).
-spec ensure() -> ok.
ensure() ->
    case ets:whereis(?COUNTERS) of
        undefined ->
            catch ets:new(?COUNTERS, [named_table, public, set,
                                      {read_concurrency, true},
                                      {write_concurrency, true}]),
            ok;
        _ ->
            ok
    end,
    case ets:whereis(?CREDIT) of
        undefined ->
            catch ets:new(?CREDIT, [named_table, public, set,
                                    {read_concurrency, true},
                                    {write_concurrency, true}]),
            ok;
        _ ->
            ok
    end,
    ok.

%% @doc Bump a counter by one.
-spec inc(atom()) -> integer().
inc(Counter) when is_atom(Counter) ->
    inc(Counter, 1).

%% @doc Bump a counter by N (N >= 0 on the shed paths; exactly the
%% dropped count on the send-failure path).
-spec inc(atom(), non_neg_integer()) -> integer().
inc(Counter, N) when is_atom(Counter), is_integer(N), N >= 0 ->
    ensure(),
    ets:update_counter(?COUNTERS, Counter, N, {Counter, 0}).

%% @doc Read a counter (0 when never bumped).
-spec get(atom()) -> integer().
get(Counter) when is_atom(Counter) ->
    ensure(),
    case ets:lookup(?COUNTERS, Counter) of
        [{Counter, Value}] -> Value;
        [] -> 0
    end.

%% @doc Every counter and its value (the scrape path for load runs).
-spec snapshot() -> [{atom(), integer()}].
snapshot() ->
    ensure(),
    ets:tab2list(?COUNTERS).

%% @doc Map a connection stop cause (as recorded in `indra_conn' state)
%% to its aggregate counter. Unknown causes stay visible instead of
%% vanishing into a catch-all bucket shared with a real event.
-spec stop_counter(atom()) -> atom().
stop_counter(connect_timeout) -> edge_stop_connect_timeout_total;
stop_counter(keepalive_timeout) -> edge_stop_keepalive_timeout_total;
stop_counter(peer_closed) -> edge_stop_peer_closed_total;
stop_counter(tcp_error) -> edge_stop_tcp_error_total;
stop_counter(protocol_error) -> edge_stop_protocol_error_total;
stop_counter(send_failed) -> edge_stop_send_failed_total;
stop_counter(ingress_overloaded) -> edge_stop_ingress_overloaded_total;
stop_counter(call_timeout) -> edge_stop_call_timeout_total;
stop_counter(call_failed) -> edge_stop_call_failed_total;
stop_counter(hold_overflow) -> edge_stop_hold_overflow_total;
stop_counter(kernel_close) -> edge_stop_kernel_close_total;
stop_counter(client_disconnect) -> edge_stop_client_disconnect_total;
stop_counter(_) -> edge_stop_unknown_total.

%% @doc Dispatch-time admission for one PublishOut frame.
%%
%% Returns `{admit, Slowed}' (frame may be cast; `Slowed' is the slowed
%% flag after the update), `{admit_over_cap, slowed}' (QoS 1 admitted
%% past the cap because no deferral exists yet: counted, never shed) or
%% `{shed, Slowed}' (QoS 0 refused: counted, never cast). `Size' is the
%% BrokerLink body size (meta + payload bytes), the same measure the
%% connection reports back in {@link egress_released/3}.
-spec egress_admit(non_neg_integer(), 0..2, non_neg_integer()) ->
    {admit, boolean()} | {admit_over_cap, boolean()} | {shed, boolean()}.
egress_admit(ConnId, Qos, Size)
  when is_integer(ConnId), ConnId >= 0,
       is_integer(Qos), Qos >= 0, Qos =< 2,
       is_integer(Size), Size >= 0 ->
    ensure(),
    {UsedF, UsedB, Slowed} = credit_row(ConnId),
    NewF = UsedF + 1,
    NewB = UsedB + Size,
    case NewF > ?CAP_FRAMES orelse NewB > ?CAP_BYTES of
        false ->
            admit_below_cap(ConnId, NewF, NewB, Slowed);
        true when Qos =:= 0 ->
            shed_newcomer(ConnId, NewF, NewB, Slowed);
        true ->
            admit_over_cap(ConnId, NewF, NewB, Slowed)
    end.

%% @doc Report PublishOut frames written to the client socket. `Frames'
%% and `Bytes' use the same body measure as {@link egress_admit/3}.
%% Returns `{recovered, UsedF, UsedB}' exactly on the slowed -> healthy
%% transition (the caller emits one flow-control frame then), else
%% `{ok, UsedF, UsedB}'.
-spec egress_released(non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    {recovered | ok, integer(), integer()}.
egress_released(ConnId, Frames, Bytes)
  when is_integer(ConnId), ConnId >= 0,
       is_integer(Frames), Frames >= 0,
       is_integer(Bytes), Bytes >= 0 ->
    ensure(),
    case ets:lookup(?CREDIT, ConnId) of
        [] ->
            {ok, 0, 0};
        [{ConnId, _, _, _}] ->
            NewF = ets:update_counter(?CREDIT, ConnId, {2, -Frames}),
            NewB = ets:update_counter(?CREDIT, ConnId, {3, -Bytes}),
            release_row(ConnId, NewF, NewB)
    end.

%% @doc Read one credit account (`{ok, {UsedFrames, UsedBytes,
%% Slowed}}' or `{error, not_found}').
-spec credit_snapshot(non_neg_integer()) ->
    {ok, {integer(), integer(), boolean()}} | {error, not_found}.
credit_snapshot(ConnId) when is_integer(ConnId), ConnId >= 0 ->
    ensure(),
    case ets:lookup(?CREDIT, ConnId) of
        [{ConnId, UsedF, UsedB, Slowed}] -> {ok, {UsedF, UsedB, Slowed}};
        [] -> {error, not_found}
    end.

%% @doc Delete one credit account (connection death; idempotent, so the
%% registry DOWN reap and the connection's own exit can both call it).
-spec credit_delete(non_neg_integer()) -> ok.
credit_delete(ConnId) when is_integer(ConnId), ConnId >= 0 ->
    ensure(),
    ets:delete(?CREDIT, ConnId),
    ok.

%% @doc Record one counted-active re-arm sample: the gauge keeps the
%% largest mailbox length seen, never a sum. Read-modify-write is fine
%% here: re-arms are infrequent (one per N socket messages), never hot
%% path, and a lost race only delays the maximum by one sample.
-spec note_passive(non_neg_integer()) -> ok.
note_passive(QueueLen) when is_integer(QueueLen), QueueLen >= 0 ->
    ensure(),
    case ets:lookup(?COUNTERS, edge_send_pending_bytes_max) of
        [{_, Max}] when Max >= QueueLen ->
            ok;
        _ ->
            ets:insert(?COUNTERS, {edge_send_pending_bytes_max, QueueLen}),
            ok
    end.

%%====================================================================
%% Internal helpers
%%====================================================================

%% @private Read one credit row, creating the zeroed account (full
%% initial window: a fresh subscriber needs no round trip) on first use.
credit_row(ConnId) ->
    case ets:lookup(?CREDIT, ConnId) of
        [{ConnId, UsedF, UsedB, Slowed}] ->
            {UsedF, UsedB, Slowed};
        [] ->
            ets:insert_new(?CREDIT, {ConnId, 0, 0, false}),
            case ets:lookup(?CREDIT, ConnId) of
                [{ConnId, UsedF, UsedB, Slowed}] -> {UsedF, UsedB, Slowed};
                [] -> {0, 0, false}
            end
    end.

%% @private Below-cap admission. A lingering slowed flag clears only
%% below half cap (hysteresis); the release path normally clears it
%% first, so this arm is the backstop, not the fast path.
admit_below_cap(ConnId, NewF, NewB, true)
  when NewF < ?LOW_FRAMES, NewB < ?LOW_BYTES ->
    ets:update_element(?CREDIT, ConnId, [{2, NewF}, {3, NewB}, {4, false}]),
    inc(edge_recovered_total),
    {admit, false};
admit_below_cap(ConnId, NewF, NewB, Slowed) ->
    ets:update_element(?CREDIT, ConnId, [{2, NewF}, {3, NewB}]),
    {admit, Slowed}.

%% @private QoS 0 past the cap: shed the newcomer (dispatch-time refusal
%% costs one counter increment; reaching into another process's mailbox
%% to evict the oldest would put surgery on the hot dispatch path).
shed_newcomer(ConnId, _NewF, _NewB, Slowed) ->
    inc(edge_dispatch_qos0_shed_total),
    {shed, mark_slowed(ConnId, Slowed)}.

%% @private QoS 1 past the cap: admit anyway (no deferral exists yet, so
%% shedding would be silent loss) and count the over-cap admission.
admit_over_cap(ConnId, NewF, NewB, Slowed) ->
    ets:update_element(?CREDIT, ConnId, [{2, NewF}, {3, NewB}, {4, true}]),
    inc(edge_egress_qos1_over_cap_total),
    {admit_over_cap, mark_slowed(ConnId, Slowed)}.

%% @private Set the slowed flag, emitting the transition event exactly
%% once per excursion past the cap. Returns the flag after the update.
mark_slowed(_ConnId, true) ->
    true;
mark_slowed(ConnId, false) ->
    ets:update_element(?CREDIT, ConnId, {4, true}),
    inc(edge_slowed_total),
    true.

%% @private Post-release bookkeeping. Counters can only drift negative
%% if a release ever outruns its admission (a bug, not a load shape):
%% clamp back to zero rather than letting a negative balance admit
%% forever. The slowed flag clears only below half cap.
release_row(ConnId, _NewF, _NewB) when _NewF < 0; _NewB < 0 ->
    ets:insert(?CREDIT, {ConnId, 0, 0, false}),
    {ok, 0, 0};
release_row(ConnId, NewF, NewB) ->
    case ets:lookup(?CREDIT, ConnId) of
        [{ConnId, _, _, true}] when NewF < ?LOW_FRAMES, NewB < ?LOW_BYTES ->
            ets:update_element(?CREDIT, ConnId, {4, false}),
            inc(edge_recovered_total),
            {recovered, NewF, NewB};
        _ ->
            {ok, NewF, NewB}
    end.
