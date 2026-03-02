//! Database module for persistent state storage.
//!
//! This module provides ACID-compliant storage using redb for
//! VM state persistence with atomic transactions and concurrent access safety.
//!
//! The database is opened and closed per-operation to avoid holding OS-level
//! file locks between transactions, allowing CLI and serve to coexist.

use crate::config::VmRecord;
use crate::error::{Error, Result};
use parking_lot::Mutex;
use redb::{Database, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Table for storing VM records (name -> JSON-serialized VmRecord).
const VMS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("vms");

/// Table for storing global configuration settings.
const CONFIG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("config");

/// Extension trait to convert errors into `Error::database`.
trait DbResultExt<T> {
    fn db_err(self, operation: impl Into<String>) -> Result<T>;
}

impl<T, E: std::fmt::Display> DbResultExt<T> for std::result::Result<T, E> {
    fn db_err(self, operation: impl Into<String>) -> Result<T> {
        self.map_err(|e| Error::database(operation, e.to_string()))
    }
}

/// Thread-safe database handle for smolvm state persistence.
///
/// Each operation opens the database, runs a transaction, and closes the handle,
/// so the OS file lock is held only for the duration of each operation (~1-5ms).
#[derive(Clone, Debug)]
pub struct SmolvmDb {
    path: PathBuf,
    /// Serializes database opens within a single process. redb's OS file lock
    /// prevents cross-process conflicts, but within a process only one
    /// `Database::create()` can be active at a time.
    lock: Arc<Mutex<()>>,
}

impl SmolvmDb {
    /// Open the database, run a closure, and drop the handle.
    fn with_db<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Database) -> Result<T>,
    {
        let _guard = self.lock.lock();
        let db = Database::create(&self.path).db_err("open database")?;
        f(&db)
    }

    /// Open the database at the default location.
    ///
    /// Default path: `~/Library/Application Support/smolvm/server/smolvm.redb` (macOS)
    /// or `~/.local/share/smolvm/server/smolvm.redb` (Linux)
    ///
    /// If the database doesn't exist, it will be created.
    pub fn open() -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_at(&path)
    }

    /// Open the database at a specific path.
    ///
    /// Creates parent directories if they don't exist.
    pub fn open_at(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).db_err("create directory")?;
        }

        let instance = Self {
            path: path.to_path_buf(),
            lock: Arc::new(Mutex::new(())),
        };

        instance.init_tables()?;
        Ok(instance)
    }

    /// Get the default database path.
    fn default_path() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir().ok_or_else(|| {
            Error::database_unavailable("could not determine local data directory")
        })?;
        Ok(data_dir.join("smolvm").join("server").join("smolvm.redb"))
    }

    /// Initialize database tables.
    fn init_tables(&self) -> Result<()> {
        self.with_db(|db| {
            let write_txn = db.begin_write().db_err("begin write transaction")?;
            write_txn.open_table(VMS_TABLE).db_err("create vms table")?;
            write_txn
                .open_table(CONFIG_TABLE)
                .db_err("create config table")?;
            write_txn.commit().db_err("commit table creation")?;
            Ok(())
        })
    }

    // ========================================================================
    // VM Operations
    // ========================================================================

    /// Insert or update a VM record.
    pub fn insert_vm(&self, name: &str, record: &VmRecord) -> Result<()> {
        let json = serde_json::to_vec(record).db_err("serialize vm record")?;

        self.with_db(|db| {
            let write_txn = db.begin_write().db_err("begin write transaction")?;
            {
                let mut table = write_txn.open_table(VMS_TABLE).db_err("open vms table")?;
                table
                    .insert(name, json.as_slice())
                    .db_err(format!("insert vm '{}'", name))?;
            }
            write_txn.commit().db_err("commit vm insert")?;
            Ok(())
        })
    }

    /// Insert a VM record only if it doesn't already exist.
    ///
    /// Returns `Ok(true)` if inserted, `Ok(false)` if already exists.
    /// This provides atomic conflict detection at the database level.
    pub fn insert_vm_if_not_exists(&self, name: &str, record: &VmRecord) -> Result<bool> {
        let json = serde_json::to_vec(record).db_err("serialize vm record")?;

        self.with_db(|db| {
            let write_txn = db.begin_write().db_err("begin write transaction")?;

            let inserted = {
                let mut table = write_txn.open_table(VMS_TABLE).db_err("open vms table")?;
                let exists = table
                    .get(name)
                    .db_err(format!("check vm '{}'", name))?
                    .is_some();

                if exists {
                    false
                } else {
                    table
                        .insert(name, json.as_slice())
                        .db_err(format!("insert vm '{}'", name))?;
                    true
                }
            };

            write_txn.commit().db_err("commit vm insert")?;
            Ok(inserted)
        })
    }

    /// Get a VM record by name.
    pub fn get_vm(&self, name: &str) -> Result<Option<VmRecord>> {
        self.with_db(|db| {
            let read_txn = db.begin_read().db_err("begin read transaction")?;
            let table = read_txn.open_table(VMS_TABLE).db_err("open vms table")?;

            match table.get(name) {
                Ok(Some(guard)) => {
                    let record: VmRecord = serde_json::from_slice(guard.value())
                        .db_err(format!("deserialize vm record '{}'", name))?;
                    Ok(Some(record))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(Error::database(format!("get vm '{}'", name), e.to_string())),
            }
        })
    }

    /// Remove a VM record by name, returning the removed record if it existed.
    ///
    /// Uses a single write transaction to atomically read and delete the record,
    /// preventing TOCTOU races with concurrent writers.
    pub fn remove_vm(&self, name: &str) -> Result<Option<VmRecord>> {
        self.with_db(|db| {
            let write_txn = db.begin_write().db_err("begin write transaction")?;

            let existing = {
                let mut table = write_txn.open_table(VMS_TABLE).db_err("open vms table")?;

                // Read and deserialize first, releasing the AccessGuard before mutation
                let record = {
                    let get_result = table.get(name).db_err(format!("get vm '{}'", name))?;
                    match get_result {
                        Some(guard) => {
                            let r: VmRecord = serde_json::from_slice(guard.value())
                                .db_err(format!("deserialize vm record '{}'", name))?;
                            Some(r)
                        }
                        None => None,
                    }
                };

                // Now safe to mutate — AccessGuard is dropped
                if record.is_some() {
                    table.remove(name).db_err(format!("remove vm '{}'", name))?;
                }
                record
            };

            write_txn.commit().db_err("commit vm removal")?;
            Ok(existing)
        })
    }

    /// List all VM records.
    pub fn list_vms(&self) -> Result<Vec<(String, VmRecord)>> {
        self.with_db(|db| {
            let read_txn = db.begin_read().db_err("begin read transaction")?;
            let table = read_txn.open_table(VMS_TABLE).db_err("open vms table")?;

            let mut vms = Vec::new();
            for entry in table.iter().db_err("iterate vms table")? {
                let (key, value) = entry.db_err("read vms entry")?;
                let name = key.value().to_string();
                let record: VmRecord = serde_json::from_slice(value.value())
                    .db_err(format!("deserialize vm record '{}'", name))?;
                vms.push((name, record));
            }

            Ok(vms)
        })
    }

    /// Update a VM record in place using a closure.
    ///
    /// Returns the updated record if found, `None` if not found.
    ///
    /// Uses a single write transaction to atomically read, mutate, and write back,
    /// preventing lost updates from concurrent writers.
    pub fn update_vm<F>(&self, name: &str, f: F) -> Result<Option<VmRecord>>
    where
        F: FnOnce(&mut VmRecord),
    {
        self.with_db(|db| {
            let write_txn = db.begin_write().db_err("begin write transaction")?;

            let updated = {
                let mut table = write_txn.open_table(VMS_TABLE).db_err("open vms table")?;

                // Read and deserialize first, releasing the AccessGuard before mutation
                let record = {
                    let get_result = table.get(name).db_err(format!("get vm '{}'", name))?;
                    match get_result {
                        Some(guard) => {
                            let r: VmRecord = serde_json::from_slice(guard.value())
                                .db_err(format!("deserialize vm record '{}'", name))?;
                            Some(r)
                        }
                        None => None,
                    }
                };

                // Now safe to mutate — AccessGuard is dropped
                match record {
                    Some(mut record) => {
                        f(&mut record);
                        let json = serde_json::to_vec(&record).db_err("serialize vm record")?;
                        table
                            .insert(name, json.as_slice())
                            .db_err(format!("update vm '{}'", name))?;
                        Some(record)
                    }
                    None => None,
                }
            };

            write_txn.commit().db_err("commit vm update")?;
            Ok(updated)
        })
    }

    /// Load all VMs into an in-memory HashMap (for compatibility layer).
    pub fn load_all_vms(&self) -> Result<HashMap<String, VmRecord>> {
        let vms = self.list_vms()?;
        Ok(vms.into_iter().collect())
    }

    // ========================================================================
    // Global Config Operations
    // ========================================================================

    /// Get a global configuration value.
    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        self.with_db(|db| {
            let read_txn = db.begin_read().db_err("begin read transaction")?;
            let table = read_txn
                .open_table(CONFIG_TABLE)
                .db_err("open config table")?;

            match table.get(key) {
                Ok(Some(guard)) => Ok(Some(guard.value().to_string())),
                Ok(None) => Ok(None),
                Err(e) => Err(Error::database(
                    format!("get config '{}'", key),
                    e.to_string(),
                )),
            }
        })
    }

    /// Set a global configuration value.
    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        self.with_db(|db| {
            let write_txn = db.begin_write().db_err("begin write transaction")?;
            {
                let mut table = write_txn
                    .open_table(CONFIG_TABLE)
                    .db_err("open config table")?;
                table
                    .insert(key, value)
                    .db_err(format!("set config '{}'", key))?;
            }
            write_txn.commit().db_err("commit config set")?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RecordState;
    use tempfile::TempDir;

    fn temp_db() -> (TempDir, SmolvmDb) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.redb");
        let db = SmolvmDb::open_at(&path).unwrap();
        (dir, db)
    }

    #[test]
    fn test_db_crud_operations() {
        let (_dir, db) = temp_db();

        // Create a VM record
        let record = VmRecord::new(
            "test-vm".to_string(),
            2,
            1024,
            vec![("/host".to_string(), "/guest".to_string(), false)],
            vec![(8080, 80)],
            false,
        );

        // Insert
        db.insert_vm("test-vm", &record).unwrap();

        // Get
        let retrieved = db.get_vm("test-vm").unwrap().unwrap();
        assert_eq!(retrieved.name, "test-vm");
        assert_eq!(retrieved.cpus, 2);
        assert_eq!(retrieved.mem, 1024);

        // Update — returns the mutated record
        let updated = db
            .update_vm("test-vm", |r| {
                r.state = RecordState::Running;
                r.pid = Some(12345);
            })
            .unwrap()
            .unwrap();
        assert_eq!(updated.state, RecordState::Running);
        assert_eq!(updated.pid, Some(12345));

        // List
        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].0, "test-vm");

        // Remove
        let removed = db.remove_vm("test-vm").unwrap().unwrap();
        assert_eq!(removed.name, "test-vm");

        // Verify removed
        assert!(db.get_vm("test-vm").unwrap().is_none());
    }

    #[test]
    fn test_db_concurrent_access() {
        let (_dir, db) = temp_db();

        // Create multiple VMs from different threads
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let name = format!("vm-{}", i);
                    let record = VmRecord::new(name.clone(), 1, 512, vec![], vec![], false);
                    db.insert_vm(&name, &record).unwrap();
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all VMs were created
        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 10);
    }

    #[test]
    fn test_config_settings() {
        let (_dir, db) = temp_db();

        // Set config
        db.set_config("test_key", "test_value").unwrap();

        // Get config
        let value = db.get_config("test_key").unwrap().unwrap();
        assert_eq!(value, "test_value");

        // Get non-existent config
        assert!(db.get_config("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_update_nonexistent_vm() {
        let (_dir, db) = temp_db();

        // Update should return None for non-existent VM
        let result = db.update_vm("nonexistent", |_| {}).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_nonexistent_vm() {
        let (_dir, db) = temp_db();

        // Remove should return None for non-existent VM
        let result = db.remove_vm("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_insert_vm_if_not_exists() {
        let (_dir, db) = temp_db();

        let record = VmRecord::new("test-vm".to_string(), 1, 512, vec![], vec![], false);

        // First insert should succeed
        let inserted = db.insert_vm_if_not_exists("test-vm", &record).unwrap();
        assert!(inserted, "first insert should succeed");

        // Second insert with same name should return false
        let inserted = db.insert_vm_if_not_exists("test-vm", &record).unwrap();
        assert!(!inserted, "second insert should fail (already exists)");

        // Verify only one VM exists
        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 1);

        // Different name should succeed
        let record2 = VmRecord::new("test-vm2".to_string(), 2, 1024, vec![], vec![], false);
        let inserted = db.insert_vm_if_not_exists("test-vm2", &record2).unwrap();
        assert!(inserted, "different name should succeed");

        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 2);
    }

    #[test]
    fn test_insert_vm_if_not_exists_concurrent() {
        let (_dir, db) = temp_db();

        // Try to insert the same name from multiple threads
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let record =
                        VmRecord::new("contested-name".to_string(), 1, 512, vec![], vec![], false);
                    db.insert_vm_if_not_exists("contested-name", &record)
                        .unwrap()
                })
            })
            .collect();

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Exactly one should have succeeded
        let success_count = results.iter().filter(|&&r| r).count();
        assert_eq!(success_count, 1, "exactly one insert should succeed");

        // Verify only one VM exists
        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 1);
    }
}
