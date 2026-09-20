%% @doc EUnit coverage for the Q3 per-connection egress credit accounts
%% (egress stage 1, `indra_edge_counters').
%%
%% Fails before the stage: no account, no bound, no shed accounting
%% exists. All tests are self-terminating (ETS rows created here are
%% deleted here) and need no sockets, processes or core.
-module(indra_egress_credit_tests).

-include_lib("eunit/include/eunit.hrl").

-define(CAP_F, 128).
-define(CAP_B, 65536).

%%====================================================================
%% Admission below the cap
%%====================================================================

%% @doc Fresh connections admit up to the frame cap with no shed and no
%% throttle events: a healthy subscriber never trips the bound.
admit_below_cap_counts_used_test() ->
    Conn = 900001,
    ShedBefore = indra_edge_counters:get(edge_dispatch_qos0_shed_total),
    try
        lists:foreach(
          fun(_) ->
              ?assertMatch({admit, false},
                           indra_edge_counters:egress_admit(Conn, 0, 200))
          end, lists:seq(1, ?CAP_F)),
        ?assertEqual({ok, {?CAP_F, ?CAP_F * 200, false}},
                     indra_edge_counters:credit_snapshot(Conn)),
        ?assertEqual(ShedBefore,
                     indra_edge_counters:get(edge_dispatch_qos0_shed_total))
    after
        indra_edge_counters:credit_delete(Conn)
    end.

%% @doc The byte leg trips first for large payloads: 8 KiB frames shed
%% well before 128 frames are reached (8 x 8 KiB = 64 KiB).
byte_leg_trips_before_frame_leg_test() ->
    Conn = 900002,
    ShedBefore = indra_edge_counters:get(edge_dispatch_qos0_shed_total),
    try
        lists:foreach(
          fun(_) ->
              ?assertMatch({admit, _},
                           indra_edge_counters:egress_admit(Conn, 0, 8192))
          end, lists:seq(1, 8)),
        ?assertMatch({shed, true},
                     indra_edge_counters:egress_admit(Conn, 0, 8192)),
        ?assertEqual(ShedBefore + 1,
                     indra_edge_counters:get(edge_dispatch_qos0_shed_total))
    after
        indra_edge_counters:credit_delete(Conn)
    end.

%%====================================================================
%% Shed vs over-cap admission
%%====================================================================

%% @doc Past the cap QoS 0 sheds the newcomer without touching the
%% account, while QoS 1 is still admitted (no deferral exists yet, so
%% shedding it would be silent loss) and counted separately.
qos0_sheds_qos1_admits_past_cap_test() ->
    Conn = 900003,
    ShedBefore = indra_edge_counters:get(edge_dispatch_qos0_shed_total),
    OverBefore = indra_edge_counters:get(edge_egress_qos1_over_cap_total),
    try
        fill_frames(Conn, ?CAP_F),
        ?assertMatch({shed, true},
                     indra_edge_counters:egress_admit(Conn, 0, 100)),
        %% Shed newcomer leaves the account untouched.
        ?assertEqual({ok, {?CAP_F, ?CAP_F * 100, true}},
                     indra_edge_counters:credit_snapshot(Conn)),
        ?assertMatch({admit_over_cap, true},
                     indra_edge_counters:egress_admit(Conn, 1, 100)),
        ?assertEqual({ok, {?CAP_F + 1, (?CAP_F + 1) * 100, true}},
                     indra_edge_counters:credit_snapshot(Conn)),
        ?assertEqual(ShedBefore + 1,
                     indra_edge_counters:get(edge_dispatch_qos0_shed_total)),
        ?assertEqual(OverBefore + 1,
                     indra_edge_counters:get(edge_egress_qos1_over_cap_total))
    after
        indra_edge_counters:credit_delete(Conn)
    end.

%%====================================================================
%% Hysteresis
%%====================================================================

%% @doc The slowed flag raises exactly once per excursion and clears
%% only below half cap: churn at the cap emits one slowed event, and
%% recovery emits one recovered event plus the release-time transition
%% marker for the flow-control frame.
slowed_recovers_with_hysteresis_test() ->
    Conn = 900004,
    SlowedBefore = indra_edge_counters:get(edge_slowed_total),
    RecBefore = indra_edge_counters:get(edge_recovered_total),
    try
        fill_frames(Conn, ?CAP_F),
        %% One past the cap: shed the newcomer and mark slowed.
        ?assertMatch({shed, true},
                     indra_edge_counters:egress_admit(Conn, 0, 100)),
        %% Still slowed just under the cap: no recovery at 127.
        ?assertMatch({ok, _, _},
                     indra_edge_counters:egress_released(Conn, 1, 100)),
        ?assertEqual({ok, {?CAP_F - 1, (?CAP_F - 1) * 100, true}},
                     indra_edge_counters:credit_snapshot(Conn)),
        %% Down below half cap: exactly one recovery.
        ?assertMatch({recovered, 63, 6300},
                     indra_edge_counters:egress_released(Conn, 64, 64 * 100)),
        ?assertEqual({ok, {63, 6300, false}},
                     indra_edge_counters:credit_snapshot(Conn)),
        %% Further releases while healthy: no more events.
        ?assertMatch({ok, _, _},
                     indra_edge_counters:egress_released(Conn, 3, 300)),
        ?assertEqual(SlowedBefore + 1, indra_edge_counters:get(edge_slowed_total)),
        ?assertEqual(RecBefore + 1, indra_edge_counters:get(edge_recovered_total))
    after
        indra_edge_counters:credit_delete(Conn)
    end.

%%====================================================================
%% Lifecycle
%%====================================================================

%% @doc Release without an account is a no-op (never negative, never a
%% crash): direct unit calls without a dispatch pass stay total.
release_without_account_is_noop_test() ->
    ?assertEqual({ok, 0, 0}, indra_edge_counters:egress_released(910001, 1, 100)).

%% @doc Deleting an account is idempotent and snapshots report it gone:
%% the connection exit and the registry DOWN reap can both fire.
delete_is_idempotent_test() ->
    Conn = 900005,
    ?assertMatch({admit, _}, indra_edge_counters:egress_admit(Conn, 0, 10)),
    ok = indra_edge_counters:credit_delete(Conn),
    ok = indra_edge_counters:credit_delete(Conn),
    ?assertEqual({error, not_found}, indra_edge_counters:credit_snapshot(Conn)).

%%====================================================================
%% Helpers
%%====================================================================

fill_frames(Conn, N) ->
    lists:foreach(
      fun(_) -> indra_edge_counters:egress_admit(Conn, 0, 100) end,
      lists:seq(1, N)).
