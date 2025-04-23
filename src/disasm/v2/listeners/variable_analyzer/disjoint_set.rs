use std::hash::Hash;

use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SetId(usize);

pub(crate) struct DisjointSet<T> {
    element_to_set: HashMap<T, SetId>,
    sets: HashMap<SetId, HashSet<T>>,
    next_id: usize,
}

impl<T: Hash + Eq + Clone> DisjointSet<T> {
    pub(crate) fn new() -> Self {
        Self {
            element_to_set: HashMap::new(),
            sets: HashMap::new(),
            next_id: 0,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SetId, &HashSet<T>)> {
        self.sets.iter()
    }

    pub(crate) fn find(&self, elem: &T) -> Option<SetId> {
        self.element_to_set.get(elem).copied()
    }

    pub(crate) fn contains(&self, elem: &T) -> bool {
        self.element_to_set.contains_key(elem)
    }

    pub(crate) fn insert(&mut self, elem: T) -> SetId {
        match &self.find(&elem) {
            Some(id) => *id,
            None => {
                let id = SetId(self.next_id);
                self.next_id += 1;
                self.element_to_set.insert(elem.clone(), id);
                self.sets.insert(id, HashSet::from([elem]));
                id
            }
        }
    }

    pub(crate) fn join_sets(&mut self, id1: &SetId, id2: &SetId) -> SetId {
        assert!(self.sets.contains_key(id1));
        assert!(self.sets.contains_key(id2));
        if id1 == id2 {
            return *id1;
        }
        let set1 = self.sets.remove(&id1).unwrap();
        let set2 = self.sets.remove(&id2).unwrap();
        let new_set: HashSet<_> = set1.union(&set2).cloned().collect();
        let new_id = SetId(self.next_id);
        self.next_id += 1;
        self.element_to_set
            .extend(new_set.iter().map(|elem| (elem.clone(), new_id)));
        self.sets.insert(new_id, new_set);
        new_id
    }

    /// Attempts to insert the element to set_id, however if the element
    /// already exists in another set, it will join the sets
    pub(crate) fn insert_join(&mut self, set_id: &SetId, elem: T) -> SetId {
        assert!(self.sets.contains_key(set_id));
        match self.find(&elem) {
            Some(id) if id != *set_id => self.join_sets(set_id, &id),
            Some(id) => id,
            None => {
                let Some(s) = self.sets.get_mut(set_id) else {
                    panic!("set_id {:?} not found", set_id);
                };
                self.element_to_set.insert(elem.clone(), *set_id);
                s.insert(elem);
                *set_id
            }
        }
    }

    pub fn join(&mut self, e1: T, e2: T) -> SetId {
        match self.find(&e1) {
            Some(id) => self.insert_join(&id, e2),
            None => {
                let e1_set = self.insert(e1);
                let e2_set = self.insert(e2);
                self.join_sets(&e1_set, &e2_set)
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_empty() {
        let ds: DisjointSet<i32> = DisjointSet::new();
        assert_eq!(ds.element_to_set.len(), 0);
        assert_eq!(ds.sets.len(), 0);
        assert_eq!(ds.next_id, 0);
    }

    #[test]
    fn test_insert_new() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(10);
        // Don't assert specific ID value (like SetId(0))
        assert!(ds.contains(&10));
        assert_eq!(ds.find(&10), Some(id1));
        assert_eq!(ds.sets.len(), 1);
        assert!(ds.sets.contains_key(&id1)); // Verify the ID exists
        assert_eq!(ds.sets[&id1].len(), 1);
        assert!(ds.sets[&id1].contains(&10));

        let id2 = ds.insert(20);
        // Don't assert specific ID value (like SetId(1))
        assert_ne!(id1, id2); // Ensure a different ID was generated
        assert!(ds.contains(&20));
        assert_eq!(ds.find(&20), Some(id2));
        assert_eq!(ds.sets.len(), 2);
        assert!(ds.sets.contains_key(&id2)); // Verify the ID exists
        assert_eq!(ds.sets[&id2].len(), 1);
        assert!(ds.sets[&id2].contains(&20));
    }

    #[test]
    fn test_insert_existing() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(10);
        let initial_next_id = ds.next_id;
        let id2 = ds.insert(10); // Re-insert
        assert_eq!(id1, id2); // Should return the same ID
        assert_eq!(ds.find(&10), Some(id1));
        assert_eq!(ds.sets.len(), 1);
        assert_eq!(ds.next_id, initial_next_id); // next_id should not increment
    }

    #[test]
    fn test_contains() {
        let mut ds = DisjointSet::new();
        ds.insert(10);
        assert!(ds.contains(&10));
        assert!(!ds.contains(&20));
    }

    #[test]
    fn test_find() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(10);
        let id2 = ds.insert(20);
        assert_eq!(ds.find(&10), Some(id1));
        assert_eq!(ds.find(&20), Some(id2));
        assert_eq!(ds.find(&30), None);
    }

    #[test]
    fn test_join_sets() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(10);
        let id2 = ds.insert(20);
        let id3 = ds.insert(30);
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id2, id3);

        let new_id = ds.join_sets(&id1, &id2);
        // Don't assert specific ID value (like SetId(3))
        assert_ne!(new_id, id1); // Should be a new ID
        assert_ne!(new_id, id2); // Should be a new ID
        assert_ne!(new_id, id3); // Should be different from other existing IDs

        // Check old IDs are gone
        assert!(!ds.sets.contains_key(&id1));
        assert!(!ds.sets.contains_key(&id2));
        // Check new ID exists
        assert!(ds.sets.contains_key(&new_id));

        // Check elements point to new ID
        assert_eq!(ds.find(&10), Some(new_id));
        assert_eq!(ds.find(&20), Some(new_id));
        // Check other element is unaffected
        assert_eq!(ds.find(&30), Some(id3));

        // Check contents of new set
        let new_set = ds.sets.get(&new_id).unwrap();
        assert!(new_set.contains(&10));
        assert!(new_set.contains(&20));
        assert!(!new_set.contains(&30));
        assert_eq!(new_set.len(), 2);

        // Check contents of other set
        let set3 = ds.sets.get(&id3).unwrap();
        assert!(set3.contains(&30));
        assert!(!set3.contains(&10));
        assert!(!set3.contains(&20));
        assert_eq!(set3.len(), 1);

        // Check joining with self
        let initial_next_id = ds.next_id;
        let same_id = ds.join_sets(&new_id, &new_id);
        assert_eq!(same_id, new_id); // Should return the same ID
        assert_eq!(ds.find(&10), Some(new_id));
        assert_eq!(ds.find(&20), Some(new_id));
        assert_eq!(ds.next_id, initial_next_id); // No new ID created
    }

    #[test]
    fn test_insert_join_new_element() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(10);

        // Insert 20 (which is new) "into" set id1.
        // Current implementation inserts 20 into its own *new* set.
        let id2 = ds.insert_join(&id1, 20);
        assert_eq!(id1, id2);

        // Check state after insert_join
        assert_eq!(ds.find(&10), Some(id1)); // 10 remains in its original set
        assert_eq!(ds.find(&20), Some(id2)); // 20 is in its own new set
        assert_eq!(ds.sets.len(), 1); // Two sets should exist

        // Check sets content
        assert!(ds.sets.contains_key(&id1));
        assert!(ds.sets.contains_key(&id2));
        assert!(ds.sets[&id1].contains(&10));
        assert!(ds.sets[&id1].contains(&20));
    }

    #[test]
    fn test_insert_join_existing_element_different_set() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(10);
        let id2 = ds.insert(20);
        assert_ne!(id1, id2);

        // Insert 20 (which is in set id2) into set id1
        // This should join the two sets.
        let new_id = ds.insert_join(&id1, 20);
        // Don't assert specific ID value (like SetId(2))
        assert_ne!(new_id, id1); // Should be a new ID for the joined set
        assert_ne!(new_id, id2); // Should be a new ID for the joined set

        // Check elements point to new ID
        assert_eq!(ds.find(&10), Some(new_id));
        assert_eq!(ds.find(&20), Some(new_id));

        // Check old sets are gone, new one exists
        assert!(!ds.sets.contains_key(&id1));
        assert!(!ds.sets.contains_key(&id2));
        assert!(ds.sets.contains_key(&new_id));
        assert_eq!(ds.sets.len(), 1); // Only the joined set should remain

        // Check new set content
        let new_set = ds.sets.get(&new_id).unwrap();
        assert!(new_set.contains(&10));
        assert!(new_set.contains(&20));
        assert_eq!(new_set.len(), 2);
    }

    #[test]
    fn test_insert_join_existing_element_same_set() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(10);
        let initial_next_id = ds.next_id;

        // Insert 10 into set id1 (already there)
        let result_id = ds.insert_join(&id1, 10);
        assert_eq!(result_id, id1); // Should return the existing ID

        // Check state hasn't changed
        assert_eq!(ds.find(&10), Some(id1));
        assert_eq!(ds.sets.len(), 1);
        assert!(ds.sets.contains_key(&id1));
        assert_eq!(ds.sets[&id1].len(), 1);
        assert!(ds.sets[&id1].contains(&10));
        assert_eq!(ds.next_id, initial_next_id); // No new IDs generated
    }

    #[test]
    fn test_join_both_new() {
        let mut ds: DisjointSet<i32> = DisjointSet::new();
        // 10 -> new set id_a, 20 -> new set id_b, join -> new set id_c
        let id = ds.join(10, 20);
        // Don't assert specific ID value (like SetId(2))
        assert!(ds.sets.contains_key(&id)); // Verify the ID exists

        assert_eq!(ds.find(&10), Some(id));
        assert_eq!(ds.find(&20), Some(id));
        assert_eq!(ds.sets.len(), 1);
        let set = ds.sets.get(&id).unwrap();
        assert!(set.contains(&10));
        assert!(set.contains(&20));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_join_first_exists() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(10);
        // 10 exists (id1), 20 -> new set id_b, join -> new set id_c
        let id_join = ds.join(10, 20);
        // Don't assert specific ID value (like SetId(2))
        assert_eq!(id_join, id1); // Should be a new ID for the joined set
        assert!(ds.sets.contains_key(&id_join)); // Verify the ID exists

        assert_eq!(ds.find(&10), Some(id_join));
        assert_eq!(ds.find(&20), Some(id_join));
        assert_eq!(ds.sets.len(), 1); // Only the joined set should exist
        let set = ds.sets.get(&id_join).unwrap();
        assert!(set.contains(&10));
        assert!(set.contains(&20));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_join_second_exists() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(20); // ID for element 20
                                 // 10 -> new set id_a, 20 exists (id1), join -> new set id_c
        let id_join = ds.join(10, 20);
        // Don't assert specific ID value (like SetId(2))
        assert_ne!(id_join, id1); // Should be a new ID for the joined set
        assert!(ds.sets.contains_key(&id_join)); // Verify the ID exists

        assert_eq!(ds.find(&10), Some(id_join));
        assert_eq!(ds.find(&20), Some(id_join));
        assert!(!ds.sets.contains_key(&id1)); // Original set should be gone
        assert_eq!(ds.sets.len(), 1); // Only the joined set should exist
        let set = ds.sets.get(&id_join).unwrap();
        assert!(set.contains(&10));
        assert!(set.contains(&20));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_join_both_exist_different_sets() {
        let mut ds = DisjointSet::new();
        let id1 = ds.insert(10);
        let id2 = ds.insert(20);
        assert_ne!(id1, id2);
        // 10 exists (id1), 20 exists (id2), join -> new set id_c
        let id_join = ds.join(10, 20);
        // Don't assert specific ID value (like SetId(2))
        assert_ne!(id_join, id1); // Should be a new ID for the joined set
        assert_ne!(id_join, id2); // Should be a new ID for the joined set
        assert!(ds.sets.contains_key(&id_join)); // Verify the ID exists

        assert_eq!(ds.find(&10), Some(id_join));
        assert_eq!(ds.find(&20), Some(id_join));
        assert!(!ds.sets.contains_key(&id1)); // Original set should be gone
        assert!(!ds.sets.contains_key(&id2)); // Original set should be gone
        assert_eq!(ds.sets.len(), 1); // Only the joined set should exist
        let set = ds.sets.get(&id_join).unwrap();
        assert!(set.contains(&10));
        assert!(set.contains(&20));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_join_both_exist_same_set() {
        let mut ds = DisjointSet::new();
        let _id1 = ds.insert(10); // Insert 10, get id_a
        let _id2 = ds.insert(20); // Insert 20, get id_b
        let id_join1 = ds.join(10, 20); // Join them, get id_c
                                        // Don't assert specific ID value for id_join1
        assert!(ds.sets.contains_key(&id_join1));
        assert_eq!(ds.find(&10), Some(id_join1));
        assert_eq!(ds.find(&20), Some(id_join1));

        let initial_next_id = ds.next_id;
        let initial_set_count = ds.sets.len();

        // Now join again
        let id_join2 = ds.join(10, 20);
        assert_eq!(id_join2, id_join1); // Should return the existing joined ID

        // Verify state hasn't changed unexpectedly
        assert_eq!(ds.find(&10), Some(id_join1));
        assert_eq!(ds.find(&20), Some(id_join1));
        assert_eq!(ds.sets.len(), initial_set_count); // Still the same number of sets
        assert!(ds.sets.contains_key(&id_join1)); // The joined set still exists
        assert_eq!(ds.next_id, initial_next_id); // No new IDs created in the second join
    }

    #[test]
    fn test_iter() {
        let mut ds = DisjointSet::new();
        let _id1 = ds.insert(10); // Gets set id_a
        let id2 = ds.insert(20); // Gets set id_b
        let _id3 = ds.insert(30); // Gets set id_c
        let id13 = ds.join(10, 30); // Joins sets for 10 and 30, gets set id_d

        // Verify state before iteration
        assert_eq!(ds.find(&10), Some(id13));
        assert_eq!(ds.find(&30), Some(id13));
        assert_eq!(ds.find(&20), Some(id2));
        assert_ne!(id13, id2);
        assert_eq!(ds.sets.len(), 2); // Should be two sets: {10, 30} and {20}

        let mut count = 0;
        let mut found_set13 = false;
        let mut found_set2 = false;

        for (id, set) in ds.iter() {
            count += 1;
            if *id == id13 {
                // The joined set of 10 and 30
                assert!(set.contains(&10));
                assert!(set.contains(&30));
                assert!(!set.contains(&20));
                assert_eq!(set.len(), 2);
                found_set13 = true;
            } else if *id == id2 {
                // The set containing only 20
                assert!(set.contains(&20));
                assert!(!set.contains(&10));
                assert!(!set.contains(&30));
                assert_eq!(set.len(), 1);
                found_set2 = true;
            } else {
                panic!(
                    "Unexpected set ID found during iteration: {:?}. Expected {:?} or {:?}",
                    id, id13, id2
                );
            }
        }
        assert_eq!(count, 2);
        assert!(found_set13);
        assert!(found_set2);
    }

    #[test]
    fn test_complex_joins() {
        let mut ds = DisjointSet::new();
        // Insert initial elements, get implicit IDs
        let _id1 = ds.insert(1);
        let _id2 = ds.insert(2);
        let _id3 = ds.insert(3);
        let _id4 = ds.insert(4);
        let _id5 = ds.insert(5);
        let _id6 = ds.insert(6);

        // Perform joins and store the resulting IDs
        let id12 = ds.join(1, 2);
        let id34 = ds.join(3, 4);
        let id56 = ds.join(5, 6);

        // Verify intermediate state
        assert_eq!(ds.find(&1), Some(id12));
        assert_eq!(ds.find(&2), Some(id12));
        assert_eq!(ds.find(&3), Some(id34));
        assert_eq!(ds.find(&4), Some(id34));
        assert_eq!(ds.find(&5), Some(id56));
        assert_eq!(ds.find(&6), Some(id56));
        assert_ne!(id12, id34);
        assert_ne!(id12, id56);
        assert_ne!(id34, id56);
        assert_eq!(ds.sets.len(), 3);

        // Join again
        let id1234 = ds.join(1, 3); // Joins id12 and id34

        // Verify intermediate state
        assert_eq!(ds.find(&1), Some(id1234));
        assert_eq!(ds.find(&2), Some(id1234));
        assert_eq!(ds.find(&3), Some(id1234));
        assert_eq!(ds.find(&4), Some(id1234));
        assert_eq!(ds.find(&5), Some(id56)); // Unchanged
        assert_eq!(ds.find(&6), Some(id56)); // Unchanged
        assert_ne!(id1234, id56);
        assert_eq!(ds.sets.len(), 2);

        // Final join
        let id_final = ds.join(2, 6); // Joins id1234 and id56

        // Verify final state
        assert_eq!(ds.find(&1), Some(id_final));
        assert_eq!(ds.find(&2), Some(id_final));
        assert_eq!(ds.find(&3), Some(id_final));
        assert_eq!(ds.find(&4), Some(id_final));
        assert_eq!(ds.find(&5), Some(id_final));
        assert_eq!(ds.find(&6), Some(id_final));
        assert_eq!(ds.sets.len(), 1);

        // Verify final set content
        assert!(ds.sets.contains_key(&id_final));
        let final_set = ds.sets.get(&id_final).unwrap();
        assert_eq!(final_set.len(), 6);
        for i in 1..=6 {
            assert!(final_set.contains(&i));
        }
    }
}
