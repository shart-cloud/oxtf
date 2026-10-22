use std::io::{self, Read};
use tf_limits::input::{InputBudget, exhaustion};
use tf_limits::{Limits, Resource};

fn limits(bytes: u64) -> Limits {
    Limits::default().with_input_bytes(bytes).unwrap()
}

#[test]
fn input_boundary_is_inclusive_and_refusal_is_sticky() {
    for size in [3, 4, 5] {
        let budget = InputBudget::new(limits(4));
        let result = budget.read_from(&vec![0; size][..]);
        if size <= 4 {
            assert_eq!(result.unwrap().len(), size);
            assert_eq!(budget.stats().source_bytes, size as u64);
            assert_eq!(budget.stats().file_entries, 1);
        } else {
            let first = exhaustion(&result.unwrap_err()).unwrap();
            assert_eq!(first.resource, Resource::InputBytes);
            assert_eq!(budget.stats().source_bytes, 0);
            assert_eq!(exhaustion(&budget.admit(0).unwrap_err()), Some(first));
            assert_eq!(exhaustion(&budget.root().unwrap_err()), Some(first));
        }
    }
}

#[test]
fn unbounded_readers_stop_after_one_lookahead_byte() {
    let mut reader = io::repeat(7);
    let budget = InputBudget::new(limits(4));
    struct Count<'a>(&'a mut dyn Read, usize);
    impl Read for Count<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1 += n;
            Ok(n)
        }
    }
    let mut counted = Count(&mut reader, 0);
    assert!(budget.read_from(&mut counted).is_err());
    assert_eq!(counted.1, 5);
}

#[test]
fn aggregate_and_empty_file_admission_use_distinct_counters() {
    let budget = InputBudget::new(limits(4).with_source_bytes(7).unwrap());
    budget.read_from(&b"abcd"[..]).unwrap();
    budget.read_from(&b"abc"[..]).unwrap();
    let error = budget.read_from(&b"x"[..]).unwrap_err();
    assert_eq!(exhaustion(&error).unwrap().resource, Resource::SourceBytes);
    assert_eq!(budget.stats().source_bytes, 7);
    assert_eq!(budget.stats().file_entries, 2);

    let budget = InputBudget::new(limits(4).with_file_entries(2).unwrap());
    budget.admit(0).unwrap();
    budget.read_from(io::empty()).unwrap();
    assert_eq!(budget.stats().source_bytes, 0);
    let error = budget.admit(0).unwrap_err();
    assert_eq!(exhaustion(&error).unwrap().resource, Resource::FileEntries);
}

#[test]
fn parallel_reads_cannot_overbook_storage() {
    let budget = InputBudget::new(limits(4).with_source_bytes(4).unwrap());
    let barrier = std::sync::Barrier::new(8);
    let accepted = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(|| {
                    barrier.wait();
                    budget.read_from(&b"1234"[..]).is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count()
    });
    assert_eq!(accepted, 1);
    assert_eq!(budget.stats().source_bytes, 4);
    assert_eq!(budget.stats().file_entries, 1);
}

#[test]
fn directory_and_root_limits_are_inclusive_and_cannot_overflow() {
    let budget = InputBudget::new(limits(4).with_directory_entries(1).unwrap());
    budget.directory_entry().unwrap();
    let error = budget.directory_entry().unwrap_err();
    assert_eq!(
        exhaustion(&error).unwrap().resource,
        Resource::DirectoryEntries
    );
    let budget = InputBudget::new(limits(4).with_roots(u64::MAX).unwrap());
    budget.ensure_roots(u64::MAX).unwrap();
    budget.ensure_roots(1).unwrap();
    let error = budget.root().unwrap_err();
    assert_eq!(exhaustion(&error).unwrap().resource, Resource::Roots);
    assert_eq!(budget.stats().roots, u64::MAX);
}

#[test]
fn ordinary_read_errors_do_not_become_limits() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture"))
        }
    }
    let budget = InputBudget::default();
    assert!(exhaustion(&budget.read_from(Broken).unwrap_err()).is_none());
    assert_eq!(budget.exhaustion(), None);
    budget.admit(1).unwrap();
}

#[test]
fn span_and_file_id_configuration_cannot_exceed_representation() {
    assert!(
        Limits::default()
            .with_input_bytes(u64::from(u32::MAX))
            .is_ok()
    );
    assert!(
        Limits::default()
            .with_input_bytes(u64::from(u32::MAX) + 1)
            .is_err()
    );
    assert!(
        Limits::default()
            .with_file_entries(u64::from(u32::MAX) + 1)
            .is_err()
    );
    assert!(Limits::default().with_input_bytes(0).is_err());
    assert!(Limits::default().with_source_bytes(0).is_err());
    assert!(Limits::default().with_file_entries(0).is_err());
    assert!(Limits::default().with_directory_entries(0).is_err());
    assert!(Limits::default().with_roots(0).is_err());
}

#[test]
fn construction_reservations_do_not_wrap_or_erase_prior_failure() {
    let budget = InputBudget::new(Limits::default().with_ast_nodes(u64::MAX).unwrap());
    budget.admit_ast_nodes(u64::MAX - 1).unwrap();
    let error = budget.admit_ast_nodes(2).unwrap_err();
    assert_eq!(error.resource, Resource::AstNodes);
    assert_eq!(budget.stats().ast_nodes, u64::MAX - 1);
    assert_eq!(budget.admit_ast_nodes(0), Err(error));
    assert_eq!(exhaustion(&budget.admit(0).unwrap_err()), Some(error));
}
