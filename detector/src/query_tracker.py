from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta

from detector.src.models import DetectorEvent


MAX_VALID_RESPONSES = 1
QUERY_MAX_AGE = timedelta(seconds=10)


OutstandingQueryKey = tuple[str, int, int, int]
LookupEpisodeKey = tuple[str, int, int]


@dataclass(frozen=True)
class ResponseMatch:
    query_event: DetectorEvent
    response_event: DetectorEvent
    response_index: int


@dataclass
class PendingLookupEpisode:
    query_events: dict[OutstandingQueryKey, DetectorEvent]
    valid_response_count: int = 0
    last_activity: datetime | None = None


def outstanding_query_key(event: DetectorEvent):
    return (event.query_name, event.query_type, event.query_class, event.transaction_id)


def lookup_episode_key(event: DetectorEvent):
    return (event.query_name, event.query_type, event.query_class)


class OutstandingQueryTracker:
    def __init__(self, closed_lookup_ttl: timedelta | None = QUERY_MAX_AGE):
        self._lookup_episodes: dict[LookupEpisodeKey, PendingLookupEpisode] = {}
        self._query_to_lookup: dict[OutstandingQueryKey, LookupEpisodeKey] = {}
        self._closed_lookups: dict[LookupEpisodeKey, datetime] = {}
        self._closed_lookup_ttl = closed_lookup_ttl

    def register_query(self, event: DetectorEvent):
        self.sweep(event.timestamp)
        episode_key = lookup_episode_key(event)
        if episode_key in self._closed_lookups:
            return

        episode = self._lookup_episodes.get(episode_key)
        if episode is None:
            episode = PendingLookupEpisode(query_events={}, last_activity=event.timestamp)
            self._lookup_episodes[episode_key] = episode

        query_key = outstanding_query_key(event)
        episode.query_events[query_key] = event
        episode.last_activity = event.timestamp
        self._query_to_lookup[query_key] = episode_key

    def match_response(self, event: DetectorEvent):
        self.sweep(event.timestamp)
        query_key = outstanding_query_key(event)
        episode_key = self._query_to_lookup.get(query_key)
        if episode_key is None:
            return None

        episode = self._lookup_episodes.get(episode_key)
        if episode is None:
            return None

        query_event = episode.query_events.get(query_key)
        if query_event is None:
            return None

        episode.valid_response_count += 1
        episode.last_activity = event.timestamp
        response_index = episode.valid_response_count
        if response_index >= MAX_VALID_RESPONSES:
            self.close_episode(episode_key, event.timestamp)

        return ResponseMatch(
            query_event=query_event,
            response_event=event,
            response_index=response_index,
        )

    def close_episode(self, episode_key: LookupEpisodeKey, closed_at: datetime):
        episode = self._lookup_episodes.pop(episode_key, None)
        if episode is not None:
            for query_key in episode.query_events:
                self._query_to_lookup.pop(query_key, None)
        self._closed_lookups[episode_key] = closed_at

    def sweep(self, now: datetime):
        cutoff = now - QUERY_MAX_AGE

        stale_episodes = [
            episode_key
            for episode_key, episode in self._lookup_episodes.items()
            if episode.last_activity is not None and episode.last_activity < cutoff
        ]
        for episode_key in stale_episodes:
            episode = self._lookup_episodes.pop(episode_key, None)
            if episode is None:
                continue
            for query_key in episode.query_events:
                self._query_to_lookup.pop(query_key, None)

        if self._closed_lookup_ttl is not None:
            closed_cutoff = now - self._closed_lookup_ttl
            stale_closed = [
                episode_key for episode_key, closed_at in self._closed_lookups.items() if closed_at < closed_cutoff
            ]
            for episode_key in stale_closed:
                del self._closed_lookups[episode_key]
