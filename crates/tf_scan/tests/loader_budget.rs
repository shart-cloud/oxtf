//! Cached defaults have the same logical cost across roots and adapters.
use std::path::PathBuf;

use tf_linter::ScanStatus;
use tf_scan::{Catalog, Limits, ScanRequest, scan};

const ROOT: &str = "/nonexistent/oxtf-loader-scan";
const DEFAULT: &str = "variable \"value\" {\n type = list(number)\n default = [1, 2, 3]\n}";

fn request(allowance: u64) -> ScanRequest {
    let root = PathBuf::from(ROOT);
    let mut request = ScanRequest::dirs(vec![root.clone()], false);
    request.catalog = Catalog::seed();
    request.limits = Limits::default().with_loader_steps(allowance).unwrap();
    request.overlay.extend([
        (root.join("main.tf"), DEFAULT.into()),
        (root.join("override.tf"), "".into()),
    ]);
    request
}

#[test]
fn hcl_and_json_loader_exhaustion_is_incomplete_and_preserves_failures() {
    let mut json = request(1);
    json.overlay = vec![
        (PathBuf::from(ROOT).join("override.tf.json"), "{}".into()),
        (
            PathBuf::from(ROOT).join("main.tf.json"),
            r#"{"variable":{"value":{"type":"list(number)","default":[1,2,3]}}}"#.into(),
        ),
    ];
    for mut request in [request(1), json] {
        let copy = request.try_clone().unwrap();
        assert_eq!(copy.limits.loader_steps(), 1);
        let limited = scan(copy).unwrap();
        assert_eq!(limited.result.status(), ScanStatus::Incomplete);
        let diagnostic = limited
            .result
            .diagnostics
            .iter()
            .find(|d| d.code == "coverage-budget")
            .unwrap();
        assert!(diagnostic.message.contains("loader_steps"));
        assert!(diagnostic.at.is_some());
        request
            .overlay
            .push((PathBuf::from(ROOT).join("broken.tf"), "broken = )".into()));
        let failed = scan(request).unwrap();
        assert_eq!(failed.result.status(), ScanStatus::Failed);
        assert!(
            failed
                .result
                .diagnostics
                .iter()
                .any(|d| d.code == "coverage-budget")
        );
        assert!(
            failed
                .result
                .diagnostics
                .iter()
                .any(|d| d.code == "parse-error")
        );
    }
}

#[test]
fn shared_modules_have_equal_costs_and_outcomes_with_one_or_many_workers() {
    let cost = scan(request(1000)).unwrap().analyses[0].stats.loader_steps;
    assert!(cost > 1);
    let mut base = request(cost);
    base.overlay.clear();
    base.overlay.extend([
        (PathBuf::from(ROOT).join("child/main.tf"), DEFAULT.into()),
        (PathBuf::from(ROOT).join("child/override.tf"), "".into()),
    ]);
    let roots = (0..8)
        .map(|i| PathBuf::from(ROOT).join(format!("root{i}")))
        .collect::<Vec<_>>();
    for root in &roots {
        base.overlay.push((
            root.join("main.tf"),
            "module \"first\" { source = \"../child\" }\n\
             module \"second\" { source = \"../child\" }"
                .into(),
        ));
    }
    base.input = tf_scan::ScanInput::Dirs {
        paths: roots,
        recursive: false,
    };
    for allowance in [cost - 1, cost] {
        let mut snapshots = Vec::new();
        for threads in [1, 4] {
            let mut request = base.try_clone().unwrap();
            request.threads = Some(threads);
            request.limits = request.limits.with_loader_steps(allowance).unwrap();
            let output = scan(request).unwrap();
            assert_eq!(output.analyses.len(), 8);
            let expected = if allowance < cost {
                ScanStatus::Incomplete
            } else {
                ScanStatus::Complete
            };
            assert_eq!(output.result.status(), expected);
            let counts = output
                .analyses
                .iter()
                .map(|a| a.stats.loader_steps)
                .collect::<Vec<_>>();
            assert!(counts.iter().all(|&used| used == counts[0]));
            if allowance == cost {
                assert_eq!(counts, vec![cost; 8]);
            }
            snapshots.push((
                counts,
                serde_json::to_value(output.record().diagnostics).unwrap(),
            ));
        }
        assert_eq!(snapshots[0], snapshots[1]);
    }
}
