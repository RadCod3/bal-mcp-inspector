import ballerina/http;
import ballerina/lang.runtime;
import ballerina/mcp;
import ballerina/time;

configurable int eventJournalCapacity = 1000;

isolated class EventJournal {
    private int nextSequence = 1;
    private (readonly & InspectorEvent)[] events = [];
    private boolean open = true;

    isolated function append(InspectorEvent eventTemplate) {
        lock {
            int sequence = self.nextSequence;
            self.nextSequence += 1;
            eventTemplate.sequence = sequence;
            eventTemplate.timestamp = time:utcToString(time:utcNow());
            readonly & InspectorEvent eventValue = eventTemplate.cloneReadOnly();
            self.events.push(eventValue);
            int capacity = eventJournalCapacity > 0 ? eventJournalCapacity : 1;
            if self.events.length() > capacity {
                _ = self.events.remove(0);
            }
        }
    }

    isolated function close() {
        lock {
            self.open = false;
        }
    }

    isolated function isOpen() returns boolean {
        lock {
            return self.open;
        }
    }

    isolated function after(int sequence) returns readonly & InspectorEvent[] {
        lock {
            (readonly & InspectorEvent)[] selectedEvents = [];
            foreach readonly & InspectorEvent eventValue in self.events {
                if eventValue.sequence > sequence {
                    selectedEvents.push(eventValue);
                }
            }
            return selectedEvents.cloneReadOnly();
        }
    }

    isolated function nextAfter(int sequence) returns readonly & InspectorEvent? {
        lock {
            foreach readonly & InspectorEvent eventValue in self.events {
                if eventValue.sequence > sequence {
                    return eventValue;
                }
            }
            return ();
        }
    }
}

isolated class EventStore {
    private map<EventJournal> journals = {};

    isolated function open(string connectionId) {
        lock {
            self.journals[connectionId] = new;
        }
    }

    isolated function close(string connectionId) {
        EventJournal? journal;
        lock {
            journal = self.journals[connectionId];
        }
        if journal is EventJournal {
            journal.close();
        }
    }

    isolated function remove(string connectionId) {
        lock {
            _ = self.journals.remove(connectionId);
        }
    }

    isolated function exists(string connectionId) returns boolean {
        lock {
            return self.journals.hasKey(connectionId);
        }
    }

    isolated function isOpen(string connectionId) returns boolean {
        EventJournal? journal;
        lock {
            journal = self.journals[connectionId];
        }
        return journal is EventJournal && journal.isOpen();
    }

    isolated function append(string connectionId, InspectorEvent eventValue) {
        EventJournal? journal;
        lock {
            journal = self.journals[connectionId];
        }
        if journal is EventJournal {
            journal.append(eventValue);
        }
    }

    isolated function after(string connectionId, int sequence) returns readonly & InspectorEvent[]? {
        EventJournal? journal;
        lock {
            journal = self.journals[connectionId];
        }
        if journal is EventJournal {
            return journal.after(sequence);
        }
        return ();
    }

    isolated function nextAfter(string connectionId, int sequence) returns readonly & InspectorEvent? {
        EventJournal? journal;
        lock {
            journal = self.journals[connectionId];
        }
        if journal is EventJournal {
            return journal.nextAfter(sequence);
        }
        return ();
    }
}

final EventStore eventStore = new;

isolated class InspectorClientObserver {
    private final string connectionId;

    isolated function init(string connectionId) {
        self.connectionId = connectionId;
    }

    public isolated function onEvent(readonly & mcp:ClientEvent clientEvent) {
        eventStore.append(self.connectionId, {
            sequence: 0,
            timestamp: "",
            connectionId: self.connectionId,
            eventType: clientEvent.eventType.toString(),
            eventTarget: clientEvent.eventTarget.toString(),
            eventUrl: clientEvent.eventUrl,
            httpMethod: clientEvent.httpMethod,
            statusCode: clientEvent.statusCode,
            eventHeaders: clientEvent.eventHeaders.clone(),
            eventBody: clientEvent.eventBody,
            eventMessage: clientEvent.eventMessage
        });
    }
}

// Idle streams get a comment this often so the listener's idle timeout and proxies keep them open
configurable int eventStreamHeartbeatSeconds = 20;

isolated class EventIterator {
    private final string connectionId;
    private int sequence;

    isolated function init(string connectionId, int sequence) {
        self.connectionId = connectionId;
        self.sequence = sequence;
    }

    public isolated function next() returns record {|http:SseEvent value;|}|error? {
        int heartbeatPolls = (eventStreamHeartbeatSeconds > 0 ? eventStreamHeartbeatSeconds : 1) * 5;
        int idlePolls = 0;
        while eventStore.exists(self.connectionId) {
            int currentSequence;
            lock {
                currentSequence = self.sequence;
            }
            readonly & InspectorEvent? eventValue = eventStore.nextAfter(self.connectionId, currentSequence);
            if eventValue is readonly & InspectorEvent {
                lock {
                    self.sequence = eventValue.sequence;
                }
                json eventJson = eventValue;
                http:SseEvent sseEvent = {
                    id: eventValue.sequence.toString(),
                    event: eventValue.eventType,
                    data: eventJson.toJsonString()
                };
                return {value: sseEvent};
            }
            if !eventStore.isOpen(self.connectionId) {
                return ();
            }
            idlePolls += 1;
            if idlePolls >= heartbeatPolls {
                return {value: {comment: "keepalive"}};
            }
            runtime:sleep(0.2);
        }
        return ();
    }
}

configurable int closedEventRetentionSeconds = 60;

isolated function expireEventJournal(string connectionId) {
    int retention = closedEventRetentionSeconds > 0 ? closedEventRetentionSeconds : 1;
    foreach int _ in 1 ... retention {
        runtime:sleep(1.0);
    }
    eventStore.remove(connectionId);
}

isolated function appendLifecycleEvent(string connectionId, string eventType, ConnectionState state,
        string? eventMessage = (), string? authorizationUrl = ()) {
    eventStore.append(connectionId, {
        sequence: 0,
        timestamp: "",
        connectionId,
        eventType,
        eventTarget: "inspector",
        eventMessage: eventMessage ?: state,
        authorizationUrl
    });
}
