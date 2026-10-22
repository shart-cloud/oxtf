use std::{fs, path::Path, process::Command};
use tf_fetch::{FetchRequest, fetch};
use tf_semantic::{AnalyzeOptions, FileTable, analyze_module};

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn git_fetch_preserves_files_and_literals_despite_export_attributes() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let root = tmp.path().join("root");
    fs::create_dir_all(repo.join("nested")).unwrap();
    fs::create_dir(&root).unwrap();
    let files = [
        (
            ".gitattributes",
            "*.tf export-ignore export-subst\nnested export-ignore\n",
        ),
        ("main.tf", "module \"nested\" { source = \"./nested\" }\n"),
        ("nested/.gitattributes", "*.tf export-ignore export-subst\n"),
        (
            "nested/database.tf",
            "resource \"aws_db_instance\" \"db\" {\n storage_encrypted = false\n identifier = \"$Format:%H$\"\n}\n",
        ),
    ];
    for (path, text) in files {
        fs::write(repo.join(path), text).unwrap();
    }
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    fs::write(
        root.join("main.tf"),
        format!(
            "module \"remote\" {{ source = \"git::file://{}\" }}\n",
            repo.display()
        ),
    )
    .unwrap();
    let fetched = fetch(FetchRequest::new(&root)).unwrap();
    for (path, text) in files {
        assert_eq!(
            fs::read_to_string(fetched.modules[0].directory.join(path)).unwrap(),
            text
        );
    }
    let analysis = analyze_module(&root, &AnalyzeOptions::default(), &FileTable::new());
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    assert_eq!(
        analysis
            .modules
            .iter()
            .map(|m| m.resources.len())
            .sum::<usize>(),
        1
    );
}

#[test]
fn git_fetch_still_rejects_packages_exceeding_the_download_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let root = tmp.path().join("root");
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(repo.join("large.txt"), "x".repeat(2 << 20)).unwrap();
    fs::write(repo.join("main.tf"), "").unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    fs::write(
        root.join("main.tf"),
        format!(
            "module \"remote\" {{ source = \"git::file://{}\" }}\n",
            repo.display(),
        ),
    )
    .unwrap();
    let mut request = FetchRequest::new(&root);
    request.limits.max_download_bytes = 64 << 10;
    assert!(fetch(request).is_err());
    assert!(!root.join(".terraform/modules/modules.json").exists());
}

#[test]
fn git_fetch_pins_a_subdirectory_and_nested_local_module_for_offline_scans() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let root = tmp.path().join("root");
    fs::create_dir_all(repo.join("modules/child/nested")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(
        repo.join("modules/child/main.tf"),
        "module \"nested\" { source = \"./nested\" }\n",
    )
    .unwrap();
    fs::write(
        repo.join("modules/child/nested/main.tf"),
        "resource \"test_node\" \"n\" { value = 1 }\n",
    )
    .unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "first",
        ],
    );
    let revision = git(&repo, &["rev-parse", "HEAD"]);
    fs::write(
        root.join("main.tf"),
        format!(
            "module \"remote\" {{ source = \"git::file://{}//modules/child\" }}\n",
            repo.display()
        ),
    )
    .unwrap();
    let first = fetch(FetchRequest::new(&root)).unwrap();
    assert_eq!(first.modules.len(), 2);
    assert_eq!(
        first.modules[0].revision.as_deref(),
        Some(revision.as_str())
    );
    fs::rename(&repo, tmp.path().join("unavailable")).unwrap();
    let second = fetch(FetchRequest::new(&root)).unwrap();
    assert_eq!(second.modules[0].revision, first.modules[0].revision);
    let analysis = analyze_module(&root, &AnalyzeOptions::default(), &FileTable::new());
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    assert_eq!(
        analysis
            .modules
            .iter()
            .map(|m| m.resources.len())
            .sum::<usize>(),
        1
    );
    let before = fs::read(root.join(".terraform/modules/modules.json")).unwrap();
    let mut req = FetchRequest::new(&root);
    req.refresh = true;
    assert!(fetch(req).is_err());
    assert_eq!(
        before,
        fs::read(root.join(".terraform/modules/modules.json")).unwrap()
    );
}

#[test]
#[expect(clippy::too_many_lines)]
fn refresh_records_a_new_commit_without_mutating_the_old_package() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let root = tmp.path().join("root");
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&root).unwrap();
    let commit = |value| {
        fs::write(
            repo.join("main.tf"),
            format!("resource \"test_node\" \"n\" {{ value = {value} }}\n"),
        )
        .unwrap();
        git(&repo, &["add", "."]);
        git(
            &repo,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-qm",
                "update",
            ],
        );
    };
    git(&repo, &["init", "-q"]);
    commit(1);
    fs::write(
        root.join("main.tf"),
        format!(
            "module \"a\" {{ source = \"git::file://{}\" }}\n",
            repo.display()
        ),
    )
    .unwrap();
    let mut req = FetchRequest::new(&root);
    req.data_dir = Some(".cache/modules-data".into());
    let first = fetch(req.clone()).unwrap();
    commit(2);
    let reused = fetch(req.clone()).unwrap();
    assert_eq!(first.modules[0].revision, reused.modules[0].revision);
    req.refresh = true;
    let second = fetch(req.clone()).unwrap();
    assert_ne!(first.modules[0].revision, second.modules[0].revision);
    assert_ne!(first.modules[0].directory, second.modules[0].directory);
    assert!(
        fs::read_to_string(first.modules[0].directory.join("main.tf"))
            .unwrap()
            .contains("value = 1")
    );
    let analysis = analyze_module(
        &root,
        &AnalyzeOptions {
            data_dir: req.data_dir.clone(),
            ..AnalyzeOptions::default()
        },
        &FileTable::new(),
    );
    assert!(
        analysis.diagnostics.is_empty(),
        "{:?}",
        analysis.diagnostics
    );
    assert_eq!(
        analysis.modules[1].package.as_ref().unwrap().revision,
        second.modules[0].revision
    );
    let path = second.modules[0].directory.join("main.tf");
    // Deliberate owner tampering must be detected before reusing a snapshot.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(&path, "resource \"test_node\" \"changed\" {}\n").unwrap();
    req.refresh = false;
    assert!(fetch(req).unwrap_err().contains("modified"));
}

#[test]
fn nested_remote_dependencies_are_resolved_and_credentials_never_reach_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().join("parent");
    let child = tmp.path().join("child");
    let root = tmp.path().join("root");
    for dir in [&parent, &child, &root] {
        fs::create_dir(dir).unwrap();
    }
    fs::write(child.join("main.tf"), "resource \"test_node\" \"n\" {}\n").unwrap();
    fs::write(
        parent.join("main.tf"),
        format!(
            "module \"child\" {{ source = \"git::file://{}\" }}\n",
            child.display()
        ),
    )
    .unwrap();
    for dir in [&parent, &child] {
        git(dir, &["init", "-q"]);
        git(dir, &["add", "."]);
        git(
            dir,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-qm",
                "first",
            ],
        );
    }
    fs::write(
        root.join("main.tf"),
        format!(
            "module \"parent\" {{ source = \"git::file://{}\" }}\n",
            parent.display()
        ),
    )
    .unwrap();
    let result = fetch(FetchRequest::new(&root)).unwrap();
    assert_eq!(
        result
            .modules
            .iter()
            .map(|m| m.key.as_str())
            .collect::<Vec<_>>(),
        vec!["parent", "parent.child"]
    );
    assert!(
        analyze_module(&root, &AnalyzeOptions::default(), &FileTable::new())
            .diagnostics
            .is_empty()
    );
    fs::write(
        root.join("main.tf"),
        "module \"bad\" { source = \"git::https://user:private-secret@example.test/repo\" }\n",
    )
    .unwrap();
    let error = fetch(FetchRequest::new(&root)).unwrap_err();
    assert!(!error.contains("private-secret"));
    assert!(
        !fs::read_to_string(root.join(".terraform/modules/modules.json"))
            .unwrap()
            .contains("private-secret")
    );
}
