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
            pub type [<$enum_name Sender>]<'a> = crate::disasm::v2::dispatching::EventCollector<'a, $enum_name>;

            #[allow(unused)]
            pub trait ModelEventListener: $crate::disasm::v2::dispatching::EventListener<$enum_name, $model_path> {

                $(
                    fn [<on_ $name:snake>]<'a>(&mut self, model: &mut $model_path, event: $name, sender: &mut [<$enum_name Sender>]) {
                    }
                )*

                fn on_event<'a>(&mut self, model: &mut $model_path, event: $enum_name, sender: &mut [<$enum_name Sender>]) {
                    match event {
                        $($enum_name::$name(e) => self.[<on_ $name:snake>](model, e, sender),)*
                    }
                }
            }

            impl<T: ModelEventListener> $crate::disasm::v2::dispatching::EventListener<$enum_name, $model_path> for T {
                fn on_event(&mut self, model: &mut $model_path, event: $enum_name, sender: &mut [<$enum_name Sender>]) {
                    match event {
                        $($enum_name::$name(e) => self.[<on_ $name:snake>](model, e, sender),)*
                    }
                }
            }
        }
    }
}
pub(crate) use event_types_enum;

/// Event collector for collecting events published by event listener.
pub struct EventCollector<'a, E> {
    queue: &'a mut Vec<E>,
}

impl<'a, E> EventCollector<'a, E> {
    fn new(queue: &'a mut Vec<E>) -> Self {
        EventCollector { queue }
    }

    pub fn publish(&mut self, event: E) {
        self.queue.push(event);
    }
}

pub trait EventListener<E, M> {
    fn on_event(&mut self, model: &mut M, event: E, collector: &mut EventCollector<E>);
}

pub struct EventPublisher<E, M> {
    listeners: Vec<Box<dyn EventListener<E, M>>>,
    work_list: VecDeque<E>,
}

impl<E: Copy, M> EventPublisher<E, M> {
    pub fn new() -> Self {
        EventPublisher {
            listeners: Vec::new(),
            work_list: VecDeque::new(),
        }
    }

    pub fn add_listener(&mut self, listener: Box<dyn EventListener<E, M>>) {
        self.listeners.push(listener);
    }

    pub fn publish<T: Into<E>>(&mut self, event: T) {
        self.work_list.push_back(event.into());
    }

    pub fn process_events(&mut self, model: &mut M) {
        let mut added = Vec::new();
        let mut collector = EventCollector::new(&mut added);
        while let Some(event) = self.work_list.pop_front() {
            for listener in &mut self.listeners {
                listener.on_event(model, event, &mut collector);
            }
        }
        self.work_list.extend(added);
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
    fn test_listener_publishes_new_event_collected() {
        let mut model = TestModel::default();
        let mut publisher: EventPublisher<TestEvent, TestModel> = EventPublisher::new();

        let event_b_to_publish = EventB { val_b: 95 };
        let listener = TestListener::new(Some(event_b_to_publish.clone().into())); // Publish EventB on EventA

        publisher.add_listener(Box::new(listener.clone()));

        let event_a = EventA { val_a: 100 };
        publisher.publish(event_a);

        // Process the first event (EventA)
        publisher.process_events(&mut model);

        // Check that EventA was received
        let received = listener.received_events();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0], TestEvent::EventA(event_a));

        // Check that EventB was added to the work list by the collector
        assert_eq!(publisher.work_list.len(), 1);
        assert_eq!(
            publisher.work_list[0],
            TestEvent::EventB(event_b_to_publish)
        );
        assert_eq!(model.counter, 1); // Model mutated once so far
    }

    #[test]
    fn test_collected_event_is_processed_on_next_cycle() {
        let mut model = TestModel::default();
        let mut publisher: EventPublisher<TestEvent, TestModel> = EventPublisher::new();

        let event_b_to_publish = EventB { val_b: 37 };
        // Listener will publish EventB when it receives EventA
        let listener = TestListener::new(Some(event_b_to_publish.clone().into()));

        publisher.add_listener(Box::new(listener.clone()));

        let event_a = EventA { val_a: 200 };
        publisher.publish(event_a);

        // --- First processing cycle ---
        publisher.process_events(&mut model);

        // Verify EventA processed and EventB queued
        let received_after_1 = listener.received_events();
        assert_eq!(received_after_1.len(), 1);
        assert_eq!(received_after_1[0], TestEvent::EventA(event_a));
        assert_eq!(publisher.work_list.len(), 1);
        assert_eq!(
            publisher.work_list[0],
            TestEvent::EventB(event_b_to_publish.clone())
        );
        assert_eq!(model.counter, 1);

        // --- Second processing cycle ---
        publisher.process_events(&mut model);

        // Verify EventB was processed
        let received_after_2 = listener.received_events();
        assert_eq!(received_after_2.len(), 2); // Now contains A and B
        assert_eq!(received_after_2[0], TestEvent::EventA(event_a)); // First event still there
        assert_eq!(received_after_2[1], TestEvent::EventB(event_b_to_publish)); // Second event added
        assert_eq!(publisher.work_list.len(), 0); // Queue should be empty now
        assert_eq!(model.counter, 2); // Model mutated again for EventB
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
