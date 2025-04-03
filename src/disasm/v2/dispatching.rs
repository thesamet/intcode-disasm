macro_rules! event_types_enum {
    (
        $enum_name:ident,
        $model_path:path,
        // Capture attributes, visibility, name, and fields (with visibility) for each struct
        $(
            $(#[$struct_attr:meta])*
            $vis:vis struct $name:ident {
                $($field_vis:vis $field:ident: $type:ty),* $(,)?
            }
        )*
    ) => {
        // Generate each struct using captured attributes, visibility, and fields
        $(
            $(#[$struct_attr])*
            $vis struct $name {
                $($field_vis $field: $type),*
            }
        )*

        // Generate the public Event enum
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)] // Add common derives for the Event enum
        pub enum $enum_name {
            $($name($name)),*
        }

        // Generate From impls
        $(
        impl From<$name> for $enum_name {
            fn from(event: $name) -> Self {
                $enum_name::$name(event)
            }
        }
        )*

        paste::paste! {
            // Type alias for the sender passed to listeners (it collects new events)
            pub type Sender<'a> = crate::disasm::v2::dispatching::EventCollector<'a, $enum_name>;

            #[allow(unused)]
            pub trait ModelEventListener: $crate::disasm::v2::dispatching::EventListener<$enum_name, $model_path> {

                $(
                    // Default implementation for specific event handlers
                    fn [<on_ $name:snake>](&mut self, _model: &mut $model_path, _event: $name, _sender: &mut Sender) {
                        // Default is no-op
                    }
                )*

                // Required on_event implementation dispatches to specific handlers
                fn on_event(&mut self, model: &mut $model_path, event: $enum_name, sender: &mut Sender) {
                    match event {
                        $($enum_name::$name(e) => self.[<on_ $name:snake>](model, e, sender),)*
                    }
                }
            }

            // Blanket implementation to satisfy the core EventListener trait using the ModelEventListener dispatch
            impl<T: ModelEventListener + ?Sized> $crate::disasm::v2::dispatching::EventListener<$enum_name, $model_path> for T {
                fn on_event(&mut self, model: &mut $model_path, event: $enum_name, sender: &mut Sender) {
                    // Directly call the on_event defined in ModelEventListener which handles the dispatch
                   <T as ModelEventListener>::on_event(self, model, event, sender);
                }
            }
        }
    }
}
pub(crate) use event_types_enum;

/// Collects events published by listeners during event processing.
/// These collected events are typically added to the main queue afterwards.
pub struct EventCollector<'a, E> {
    queue: &'a mut Vec<E>,
}

impl<'a, E> EventCollector<'a, E> {
    /// Creates a new collector wrapping a mutable reference to a queue.
    /// Usually crate-internal, used by the publisher.
    pub(crate) fn new(queue: &'a mut Vec<E>) -> Self {
        EventCollector { queue }
    }

    /// Publishes an event by adding it to the collector's queue.
    /// Accepts any type convertible into the event type `E`.
    pub fn publish<T: Into<E>>(&mut self, event: T) {
        self.queue.push(event.into());
    }
}

/// Trait for types that can listen to events.
pub trait EventListener<E, M> {
    /// Called when an event occurs.
    ///
    /// # Arguments
    ///
    /// * `model` - A mutable reference to the shared model.
    /// * `event` - The event that occurred.
    /// * `collector` - An `EventCollector` to publish new events triggered by this one.
    fn on_event(&mut self, model: &mut M, event: E, collector: &mut EventCollector<E>);
}

/// Manages listeners and dispatches events.
pub struct EventPublisher<E, M> {
    listeners: Vec<Box<dyn EventListener<E, M>>>,
    work_list: VecDeque<E>,
}

impl<E: Copy + std::fmt::Debug, M> EventPublisher<E, M> {
    /// Creates a new, empty `EventPublisher`.
    pub fn new() -> Self {
        EventPublisher {
            listeners: Vec::new(),
            work_list: VecDeque::new(),
        }
    }

    /// Adds a listener to the publisher.
    /// The listener will be notified of events during `process_events`.
    pub fn add_listener(&mut self, listener: Box<dyn EventListener<E, M>>) {
        self.listeners.push(listener);
    }

    /// Publishes an event by adding it to the work queue.
    /// Events are processed when `process_events` is called.
    /// Accepts any type convertible into the event type `E`.
    pub fn publish<T: Into<E>>(&mut self, event: T) {
        self.work_list.push_back(event.into());
    }

    /// Processes all events currently in the work queue.
    /// Listeners are notified for each event. Events published by listeners
    /// during this process are collected and added to the queue *after*
    /// the current batch is processed, ensuring they are handled in a
    /// subsequent call to `process_events` or a later iteration if looped.
    pub fn process_events(&mut self, model: &mut M) {
        let mut added_events = Vec::new();
        // Process only the events currently in the queue.
        // New events published by listeners go into `added_events`.
        while let Some(event) = self.work_list.pop_front() {
            // Create a collector for events generated during this event's processing.
            let mut collector = EventCollector::new(&mut added_events);
            for listener in &mut self.listeners {
                listener.on_event(model, event, &mut collector);
            }
            // Add the newly generated events to the main work list for the next processing cycle.
            self.work_list.extend(&added_events);
            added_events.clear();
        }
    }
}
use std::collections::VecDeque;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    // Define simple test events using the macro
    event_types_enum! {
        TestEvent, TestModel,
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] // Add derives for comparison in tests
        pub struct EventA {
            pub val_a: u32,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] // Add derives for comparison in tests
        pub struct EventB {
            pub val_b: i64,
        }
    }

    // Define a simple test model
    #[derive(Default, Debug, Clone)]
    pub struct TestModel {
        counter: u32,
    }

    // Define a listener for testing purposes
    #[derive(Clone)] // Cloneable to easily check state after processing
    struct TestListener {
        // Use Rc<RefCell> to allow tracking state changes across borrows
        received_events: Rc<RefCell<Vec<TestEvent>>>,
        publish_on_a: Option<TestEvent>, // Optionally publish another event when EventA is received
    }

    impl TestListener {
        fn new(publish_on_a: Option<TestEvent>) -> Self {
            TestListener {
                received_events: Rc::new(RefCell::new(Vec::new())),
                publish_on_a,
            }
        }

        fn received_events(&self) -> Vec<TestEvent> {
            self.received_events.borrow().clone()
        }
    }

    impl EventListener<TestEvent, TestModel> for TestListener {
        fn on_event(
            &mut self,
            model: &mut TestModel,
            event: TestEvent,
            collector: &mut EventCollector<TestEvent>,
        ) {
            // Record the received event
            self.received_events.borrow_mut().push(event);

            // Mutate the model (simple example)
            model.counter += 1;

            // Optionally publish a new event
            if let TestEvent::EventA(_) = event {
                if let Some(event_to_publish) = self.publish_on_a {
                    collector.publish(event_to_publish);
                }
            }
        }
    }

    #[test]
    fn test_single_listener_receives_event() {
        let mut model = TestModel::default();
        let mut publisher: EventPublisher<TestEvent, TestModel> = EventPublisher::new();
        let listener = TestListener::new(None);

        publisher.add_listener(Box::new(listener.clone()));
        let event_a = EventA { val_a: 42 };
        publisher.publish(event_a);

        publisher.process_events(&mut model);

        let received = listener.received_events();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0], TestEvent::EventA(event_a));
        assert_eq!(model.counter, 1); // Model was mutated
    }

    #[test]
    fn test_multiple_listeners_receive_event() {
        let mut model = TestModel::default();
        let mut publisher: EventPublisher<TestEvent, TestModel> = EventPublisher::new();
        let listener1 = TestListener::new(None);
        let listener2 = TestListener::new(None);

        publisher.add_listener(Box::new(listener1.clone()));
        publisher.add_listener(Box::new(listener2.clone()));

        let event_b = EventB { val_b: 57 };
        publisher.publish(event_b.clone()); // Clone event_b data for assertion

        publisher.process_events(&mut model);

        let received1 = listener1.received_events();
        let received2 = listener2.received_events();

        assert_eq!(received1.len(), 1);
        assert_eq!(received1[0], TestEvent::EventB(event_b.clone())); // Use cloned event_b

        assert_eq!(received2.len(), 1);
        assert_eq!(received2[0], TestEvent::EventB(event_b)); // Use original event_b

        assert_eq!(model.counter, 2); // Model mutated by both listeners
    }

    #[test]
    fn test_listener_publishes_event_processed_in_same_cycle() {
        let mut model = TestModel::default();
        let mut publisher: EventPublisher<TestEvent, TestModel> = EventPublisher::new();

        let event_b_to_publish = EventB { val_b: 95 };
        // Listener will publish EventB when it receives EventA
        let listener = TestListener::new(Some(event_b_to_publish.clone().into()));

        publisher.add_listener(Box::new(listener.clone()));

        let event_a = EventA { val_a: 100 };
        publisher.publish(event_a);

        // Process events. This should process EventA, which publishes EventB,
        // which should then also be processed in the *same* call.
        publisher.process_events(&mut model);

        // Check that both EventA and EventB were received
        let received = listener.received_events();
        assert_eq!(received.len(), 2); // Both events should have been processed
        assert_eq!(received[0], TestEvent::EventA(event_a));
        assert_eq!(received[1], TestEvent::EventB(event_b_to_publish));

        // Check that the work list is now empty
        assert!(publisher.work_list.is_empty());

        // Check that the model was mutated twice
        assert_eq!(model.counter, 2);
    }

    #[test]
    fn test_listener_published_event_processed_immediately() {
        let mut model = TestModel::default();
        let mut publisher: EventPublisher<TestEvent, TestModel> = EventPublisher::new();

        let event_b_to_publish = EventB { val_b: 37 };
        // Listener will publish EventB when it receives EventA
        let listener = TestListener::new(Some(event_b_to_publish.clone().into()));

        publisher.add_listener(Box::new(listener.clone()));

        let event_a = EventA { val_a: 200 };
        publisher.publish(event_a);

        // --- Single processing cycle ---
        // This call should process EventA, see EventB published, and then process EventB.
        publisher.process_events(&mut model);

        // Verify both EventA and EventB were processed
        let received = listener.received_events();
        assert_eq!(received.len(), 2); // Should contain A and B
        assert_eq!(received[0], TestEvent::EventA(event_a));
        assert_eq!(received[1], TestEvent::EventB(event_b_to_publish));
        assert!(publisher.work_list.is_empty()); // Queue should be empty now
        assert_eq!(model.counter, 2); // Model mutated twice
    }

    #[test]
    fn test_process_empty_queue() {
        let mut model = TestModel::default();
        let mut publisher: EventPublisher<TestEvent, TestModel> = EventPublisher::new();
        let listener = TestListener::new(None);

        publisher.add_listener(Box::new(listener.clone()));

        // No events published

        publisher.process_events(&mut model);

        let received = listener.received_events();
        assert!(received.is_empty());
        assert_eq!(publisher.work_list.len(), 0);
        assert_eq!(model.counter, 0); // Model was not mutated
    }

    #[test]
    fn test_from_impl_for_events() {
        let event_a_struct = EventA { val_a: 1 };
        let event_b_struct = EventB { val_b: 49 };

        let event_a_enum: TestEvent = event_a_struct.into();
        let event_b_enum: TestEvent = event_b_struct.into();

        assert_eq!(event_a_enum, TestEvent::EventA(event_a_struct));
        assert_eq!(event_b_enum, TestEvent::EventB(event_b_struct));
    }
}
