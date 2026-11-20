//! A stream id is released for reuse only once its RFC 6525 reset has completed in both
//! directions, or the association is gone.
//!
//! RFC 8831 §6.7 closes a data channel by resetting the outgoing stream; the peer answers by
//! resetting its own. RFC 8832 §6 lets a new channel use only an id "for which the corresponding
//! incoming and outgoing streams are unused". Releasing the id any earlier lets a new stream take
//! it, and the late reset then unregisters the new stream.
//!
//! These drive one association directly with hand-built RE-CONFIG parameters, so each half of
//! the reset can be delivered — or withheld — on its own.

use super::*;
use crate::param::Param;

const SI: StreamId = 1;

fn established() -> Association {
    let mut a = timed_test_association();
    a.open_stream(SI, PayloadProtocolIdentifier::Binary)
        .expect("open stream");
    a
}

/// The peer resetting its outgoing stream `ids`, with every DATA it sent before already here.
fn peer_reset_request(a: &Association, rsn: u32, ids: &[StreamId]) -> Box<dyn Param> {
    Box::new(ParamOutgoingResetRequest {
        reconfig_request_sequence_number: rsn,
        reconfig_response_sequence_number: 0,
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: ids.to_vec(),
    })
}

fn peer_response(rsn: u32, result: ReconfigResult) -> Box<dyn Param> {
    Box::new(ParamReconfigResponse {
        reconfig_response_sequence_number: rsn,
        result,
    })
}

fn deliver(a: &mut Association, param: Box<dyn Param>) -> Vec<Packet> {
    let mut reply = vec![];
    a.handle_reconfig_param(&param, &mut reply)
        .expect("handle reconfig param");
    reply
}

/// Sends the reset `close` queued and returns the sequence number it went out under.
fn send_queued_reset(a: &mut Association, id: StreamId) -> u32 {
    a.gather_outbound_data_and_reconfig_packets(vec![], Instant::now());
    let reset = a
        .stream_resets
        .get(&id)
        .expect("the reset is tracked once sent");
    assert_eq!(1, reset.outgoing_requests.len(), "one request in flight");
    reset.outgoing_requests[0]
}

/// The reset requests in `reply` and the streams each names.
fn reset_requests_in(reply: &[Packet]) -> Vec<Vec<StreamId>> {
    reply
        .iter()
        .flat_map(|p| &p.chunks)
        .filter_map(|c| c.as_any().downcast_ref::<ChunkReconfig>())
        .filter_map(|c| c.param_a.as_ref())
        .filter_map(|p| p.as_any().downcast_ref::<ParamOutgoingResetRequest>())
        .map(|p| p.stream_identifiers.clone())
        .collect()
}

fn responses_in(reply: &[Packet]) -> Vec<(u32, ReconfigResult)> {
    reply
        .iter()
        .flat_map(|p| &p.chunks)
        .filter_map(|c| c.as_any().downcast_ref::<ChunkReconfig>())
        .filter_map(|c| c.param_a.as_ref())
        .filter_map(|p| p.as_any().downcast_ref::<ParamReconfigResponse>())
        .map(|p| (p.reconfig_response_sequence_number, p.result))
        .collect()
}

/// Drains the event queue, returning the ids released and the streams lost.
fn drain_events(a: &mut Association) -> (Vec<StreamId>, Vec<StreamId>) {
    let (mut released, mut lost) = (vec![], vec![]);
    while let Some(event) = a.poll() {
        match event {
            Event::Stream(StreamEvent::IdReleased { id }) => released.push(id),
            Event::AssociationLost { id, .. } => lost.push(id),
            _ => {}
        }
    }
    (released, lost)
}

/// We close: the id is held after the peer answers our reset, and after the peer resets its own
/// side, and released only when both have happened — in either order.
#[test]
fn locally_closed_stream_id_is_released_only_after_both_halves() -> Result<()> {
    for answer_first in [true, false] {
        let mut a = established();
        a.stream(SI)?.close(Instant::now())?;
        assert!(a.stream_reset_pending(SI), "closing starts the reset");
        let rsn = send_queued_reset(&mut a, SI);

        let (first, second): (Box<dyn Param>, Box<dyn Param>) = if answer_first {
            (
                peer_response(rsn, ReconfigResult::SuccessPerformed),
                peer_reset_request(&a, 41, &[SI]),
            )
        } else {
            (
                peer_reset_request(&a, 41, &[SI]),
                peer_response(rsn, ReconfigResult::SuccessPerformed),
            )
        };

        let reply = deliver(&mut a, first);
        let (released, _) = drain_events(&mut a);
        assert!(
            released.is_empty() && a.stream_reset_pending(SI),
            "answer_first={answer_first}: one half done must not release the id"
        );

        let mut replies = reply;
        replies.extend(deliver(&mut a, second));
        let (released, _) = drain_events(&mut a);
        assert_eq!(
            vec![SI],
            released,
            "answer_first={answer_first}: both halves done releases the id, once"
        );
        assert!(!a.stream_reset_pending(SI));
        assert!(
            reset_requests_in(&replies).is_empty(),
            "answer_first={answer_first}: our outgoing stream is already reset; answering the \
             peer's reset with another would be redundant: {:?}",
            reset_requests_in(&replies)
        );
    }
    Ok(())
}

/// The peer closes: we answer with our own reset at once, and the id is released only when the
/// peer answers that.
#[test]
fn remotely_closed_stream_id_is_released_when_our_reset_is_answered() -> Result<()> {
    let mut a = established();

    let reply = {
        let req = peer_reset_request(&a, 7, &[SI]);
        deliver(&mut a, req)
    };
    assert_eq!(
        vec![vec![SI]],
        reset_requests_in(&reply),
        "we reset our side too"
    );
    let (released, lost) = drain_events(&mut a);
    assert_eq!(vec![SI], lost, "the stream is gone");
    assert!(released.is_empty(), "but our half is still in flight");
    assert!(a.stream_reset_pending(SI));

    let ours = a.stream_resets[&SI].outgoing_requests[0];
    deliver(
        &mut a,
        peer_response(ours, ReconfigResult::SuccessPerformed),
    );
    let (released, _) = drain_events(&mut a);
    assert_eq!(vec![SI], released);
    assert!(!a.stream_reset_pending(SI));
    Ok(())
}

/// A peer reset that arrives ahead of the peer's last DATA is performed once that DATA lands,
/// and must then be answered with our own reset exactly as on arrival. Without it the peer
/// never sees our half and neither side ever releases the id.
#[test]
fn reset_deferred_for_missing_data_still_sends_our_half() -> Result<()> {
    let mut a = established();
    let req = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 9,
        reconfig_response_sequence_number: 0,
        sender_last_tsn: a.peer_last_tsn + 1,
        stream_identifiers: vec![SI],
    };
    let reply = deliver(&mut a, Box::new(req));
    assert_eq!(
        vec![(9, ReconfigResult::InProgress)],
        responses_in(&reply),
        "the request waits for its DATA"
    );
    assert!(a.stream(SI).is_ok(), "nothing is reset yet");

    // The missing DATA, on another stream so SI has nothing left to drain.
    let reply = a.handle_data(&ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: a.peer_last_tsn + 1,
        stream_identifier: 5,
        user_data: Bytes::from_static(b"last"),
        ..Default::default()
    })?;

    assert!(a.stream(SI).is_err(), "the reset is performed");
    assert_eq!(
        vec![vec![SI]],
        reset_requests_in(&reply),
        "our own reset answers it"
    );
    assert!(
        a.stream_reset_pending(SI),
        "and is awaiting the peer's answer"
    );

    // And the id comes free once that is answered.
    let ours = a.stream_resets[&SI].outgoing_requests[0];
    deliver(
        &mut a,
        peer_response(ours, ReconfigResult::SuccessPerformed),
    );
    let (released, _) = drain_events(&mut a);
    assert_eq!(vec![SI], released);
    Ok(())
}

/// "In progress" is not an answer: the id is held until the final result.
#[test]
fn in_progress_answer_does_not_release_the_id() -> Result<()> {
    let mut a = established();
    a.stream(SI)?.close(Instant::now())?;
    let rsn = send_queued_reset(&mut a, SI);
    {
        let req = peer_reset_request(&a, 3, &[SI]);
        deliver(&mut a, req)
    };

    deliver(&mut a, peer_response(rsn, ReconfigResult::InProgress));
    let (released, _) = drain_events(&mut a);
    assert!(released.is_empty(), "in progress must not release the id");

    deliver(&mut a, peer_response(rsn, ReconfigResult::SuccessPerformed));
    let (released, _) = drain_events(&mut a);
    assert_eq!(vec![SI], released);
    Ok(())
}

/// A retransmission of a reset request already performed is answered, not performed again: by
/// then the id may belong to a new stream, and performing it would unregister that.
#[test]
fn retransmitted_reset_request_does_not_reset_a_stream_that_reused_the_id() -> Result<()> {
    let mut a = established();
    {
        let req = peer_reset_request(&a, 7, &[SI]);
        deliver(&mut a, req)
    };
    let ours = a.stream_resets[&SI].outgoing_requests[0];
    deliver(
        &mut a,
        peer_response(ours, ReconfigResult::SuccessPerformed),
    );
    drain_events(&mut a);

    a.open_stream(SI, PayloadProtocolIdentifier::Binary)?;
    let reply = {
        let req = peer_reset_request(&a, 7, &[SI]);
        deliver(&mut a, req)
    };

    let (_, lost) = drain_events(&mut a);
    assert!(
        lost.is_empty(),
        "the new stream was unregistered by an old request"
    );
    assert!(a.stream(SI).is_ok(), "the new stream must survive");
    assert_eq!(
        vec![(7, ReconfigResult::SuccessPerformed)],
        responses_in(&reply),
        "the retransmission is answered again"
    );
    assert!(reset_requests_in(&reply).is_empty());
    Ok(())
}

/// With the association gone no reset can complete, and none is needed: every id is free.
#[test]
fn closing_the_association_releases_ids_mid_reset() -> Result<()> {
    let mut a = established();
    a.open_stream(3, PayloadProtocolIdentifier::Binary)?;
    a.stream(SI)?.close(Instant::now())?;
    send_queued_reset(&mut a, SI);
    drain_events(&mut a);

    a.close(AssociationError::AssociationClosed)?;
    let (mut released, _) = drain_events(&mut a);
    released.sort_unstable();
    assert_eq!(vec![SI, 3], released, "the mid-reset id and the open one");
    assert!(!a.stream_reset_pending(SI));
    Ok(())
}

/// The retransmission limit the tests below run into, from the default timer configuration.
fn reconfig_retry_limit() -> usize {
    crate::association::timer::TimerConfig::default().max_reconfig_retrans
}

/// Lets the RE-CONFIG timer expire and returns the sequence numbers of the reset requests then
/// sent. `None` when the timer is not armed: nothing will ever be retransmitted.
fn expire_reconfig_timer(a: &mut Association) -> Option<Vec<u32>> {
    let due = a.timers.get(Timer::Reconfig)?;
    a.handle_timeout(due);
    let sent = a.gather_outbound_data_and_reconfig_packets(vec![], due);
    Some(
        sent.iter()
            .flat_map(|raw| Packet::unmarshal(raw).expect("packet").chunks)
            .filter_map(|c| {
                let c = c.as_any().downcast_ref::<ChunkReconfig>()?;
                let p = c.param_a.as_ref()?;
                p.as_any()
                    .downcast_ref::<ParamOutgoingResetRequest>()
                    .map(|p| p.reconfig_request_sequence_number)
            })
            .collect(),
    )
}

/// "In progress" leaves the request open, so it must stay on the retransmission timer: if the
/// peer's final answer is lost, retransmitting is the only way to get it again (RFC 6525
/// §5.1.1). An In Progress answer also proves the peer is there, so it restarts the retry
/// budget: a peer whose application is slow to drain is not a dead peer.
#[test]
fn reset_answered_in_progress_is_retransmitted_until_a_final_answer() -> Result<()> {
    let mut a = established();
    a.stream(SI)?.close(Instant::now())?;
    let rsn = send_queued_reset(&mut a, SI);
    {
        let req = peer_reset_request(&a, 3, &[SI]);
        deliver(&mut a, req)
    };

    // Answered In Progress more times over than the retry limit allows unanswered expiries.
    for round in 0..2 * reconfig_retry_limit() + 2 {
        deliver(&mut a, peer_response(rsn, ReconfigResult::InProgress));
        let sent = expire_reconfig_timer(&mut a).unwrap_or_else(|| {
            panic!("round {round}: the in-progress request is off the retransmission timer")
        });
        assert_eq!(
            vec![rsn],
            sent,
            "round {round}: the open request is sent again"
        );
    }
    let (released, _) = drain_events(&mut a);
    assert!(released.is_empty(), "nothing final has arrived");

    deliver(&mut a, peer_response(rsn, ReconfigResult::SuccessPerformed));
    let (released, _) = drain_events(&mut a);
    assert_eq!(vec![SI], released);
    assert_eq!(
        None,
        expire_reconfig_timer(&mut a),
        "a final answer ends the retransmissions"
    );
    Ok(())
}

/// The reset we send in answer to the peer's goes out from the receive path, not the send
/// path. It must be on the retransmission timer all the same, or losing that one packet leaves
/// the id reserved on both sides for the life of the association.
#[test]
fn reset_answering_the_peers_is_retransmitted_until_answered() -> Result<()> {
    let mut a = established();
    let reply = {
        let req = peer_reset_request(&a, 7, &[SI]);
        deliver(&mut a, req)
    };
    assert_eq!(vec![vec![SI]], reset_requests_in(&reply));
    let ours = a.stream_resets[&SI].outgoing_requests[0];

    // The next transmit pass; the reply itself went out as a control packet.
    a.gather_outbound_data_and_reconfig_packets(vec![], Instant::now());
    let sent = expire_reconfig_timer(&mut a).expect("our reset is on the retransmission timer");
    assert_eq!(vec![ours], sent, "and is sent again when it expires");

    deliver(
        &mut a,
        peer_response(ours, ReconfigResult::SuccessPerformed),
    );
    let (released, _) = drain_events(&mut a);
    assert_eq!(vec![SI], released);
    Ok(())
}

/// A peer that never answers: after the retry limit the reset is abandoned. It is no longer
/// retransmitted, and the id stays reserved — the peer may yet perform the reset, and its
/// reverse reset would then tear down whatever had reused the id. The id is released by a late
/// final answer, or by the association closing. A new reset afterwards gets a full retry budget
/// rather than inheriting the exhausted one.
#[test]
fn abandoned_reset_keeps_the_id_until_a_late_answer_or_association_close() -> Result<()> {
    let limit = reconfig_retry_limit();
    let mut a = established();
    a.open_stream(3, PayloadProtocolIdentifier::Binary)?;
    a.stream(SI)?.close(Instant::now())?;
    let rsn = send_queued_reset(&mut a, SI);

    let mut retransmissions = 0;
    while let Some(sent) = expire_reconfig_timer(&mut a) {
        if sent.is_empty() {
            break;
        }
        retransmissions += 1;
        assert!(
            retransmissions <= limit,
            "still retransmitting after {retransmissions} attempts, limit {limit}"
        );
    }
    assert_eq!(limit, retransmissions, "retransmitted up to the limit");
    assert_eq!(None, a.timers.get(Timer::Reconfig), "and then stopped");
    assert!(
        a.stream_reset_pending(SI),
        "an abandoned reset keeps the id reserved"
    );
    let (released, _) = drain_events(&mut a);
    assert!(released.is_empty());

    // A reset started now must get its own full budget.
    let now = a.timers.get(Timer::T3RTX).unwrap_or_else(Instant::now);
    a.stream(3)?.close(now)?;
    a.gather_outbound_data_and_reconfig_packets(vec![], now);
    let fresh = a.stream_resets[&3].outgoing_requests[0];
    let mut fresh_retransmissions = 0;
    while let Some(sent) = expire_reconfig_timer(&mut a) {
        if sent.is_empty() {
            break;
        }
        assert_eq!(vec![fresh], sent, "only the new request is retransmitted");
        fresh_retransmissions += 1;
        assert!(fresh_retransmissions <= limit);
    }
    assert_eq!(
        limit, fresh_retransmissions,
        "the new reset got a full budget"
    );

    // The peer answers the first one late, and resets its side: the id comes free.
    deliver(&mut a, peer_response(rsn, ReconfigResult::SuccessPerformed));
    {
        let req = peer_reset_request(&a, 21, &[SI]);
        deliver(&mut a, req)
    };
    let (released, _) = drain_events(&mut a);
    assert_eq!(
        vec![SI],
        released,
        "a late final answer still releases the id"
    );

    // The second never hears back; only the association closing frees it.
    assert!(a.stream_reset_pending(3));
    a.close(AssociationError::AssociationClosed)?;
    let (released, _) = drain_events(&mut a);
    assert_eq!(vec![3], released);
    Ok(())
}
