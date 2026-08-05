use std::collections::BTreeMap;

use crate::err::{ForensicError, ForensicResult};
use crate::traits::db::{
    ForensicColumnDef, ForensicColumnType, ForensicDb, ForensicRows, ForensicTable, ForensicValue,
    ForensicValueRef,
};

/// In-memory, multi-table mock of [`ForensicDb`].
#[derive(Clone, Debug, Default)]
pub struct InMemoryForensicDb {
    tables: BTreeMap<String, InMemoryTable>,
}

impl InMemoryForensicDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_table(mut self, table: InMemoryTable) -> Self {
        self.add_table(table);
        self
    }

    pub fn add_table(&mut self, table: InMemoryTable) {
        self.tables.insert(table.name.to_ascii_lowercase(), table);
    }
}

impl ForensicDb for InMemoryForensicDb {
    fn list_tables(&self) -> ForensicResult<Vec<String>> {
        Ok(self.tables.values().map(|t| t.name.clone()).collect())
    }

    fn table(&self, name: &str) -> ForensicResult<Box<dyn ForensicTable + '_>> {
        self.tables
            .get(&name.to_ascii_lowercase())
            .map(|t| Box::new(t.clone()) as Box<dyn ForensicTable>)
            .ok_or_else(|| {
                ForensicError::missing_data("table", format!("table '{name}' not found").into())
            })
    }
}

/// A single in-memory table: a name, column definitions, and rows.
#[derive(Clone, Debug, Default)]
pub struct InMemoryTable {
    name: String,
    columns: Vec<ForensicColumnDef>,
    rows: Vec<Vec<ForensicValue>>,
}

impl InMemoryTable {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            columns: Vec::new(),
            rows: Vec::new(),
        }
    }

    pub fn with_column(
        mut self,
        name: impl Into<String>,
        col_type: ForensicColumnType,
        nullable: bool,
    ) -> Self {
        self.columns.push(ForensicColumnDef {
            name: name.into(),
            col_type,
            nullable,
        });
        self
    }

    pub fn with_row(mut self, row: Vec<ForensicValue>) -> Self {
        self.add_row(row);
        self
    }

    pub fn add_row(&mut self, row: Vec<ForensicValue>) {
        self.rows.push(row);
    }
}

impl ForensicTable for InMemoryTable {
    fn name(&self) -> &str {
        &self.name
    }

    fn columns(&self) -> &[ForensicColumnDef] {
        &self.columns
    }

    fn iter_rows(&self) -> ForensicResult<Box<dyn ForensicRows + '_>> {
        Ok(Box::new(InMemoryRows {
            columns: &self.columns,
            rows: &self.rows,
            position: -1,
        }))
    }

    fn row_count(&self) -> Option<u64> {
        Some(self.rows.len() as u64)
    }
}

struct InMemoryRows<'a> {
    columns: &'a [ForensicColumnDef],
    rows: &'a [Vec<ForensicValue>],
    position: isize,
}

impl<'a> ForensicRows for InMemoryRows<'a> {
    fn column_count(&self) -> usize {
        self.columns.len()
    }

    fn column_name(&self, i: usize) -> Option<&str> {
        self.columns.get(i).map(|c| c.name.as_str())
    }

    fn column_names(&self) -> Vec<&str> {
        self.columns.iter().map(|c| c.name.as_str()).collect()
    }

    fn column_type(&self, i: usize) -> ForensicColumnType {
        self.columns
            .get(i)
            .map(|c| c.col_type)
            .unwrap_or(ForensicColumnType::Null)
    }

    fn next(&mut self) -> ForensicResult<bool> {
        self.position += 1;
        Ok((self.position as usize) < self.rows.len())
    }

    fn read_ref(&self, i: usize) -> ForensicResult<ForensicValueRef<'_>> {
        let row_idx = self.position as usize;
        let row = self
            .rows
            .get(row_idx)
            .ok_or_else(ForensicError::no_more_data)?;
        let val = row.get(i).ok_or_else(|| {
            ForensicError::missing_data(
                "column",
                format!("column index {i} out of bounds").into(),
            )
        })?;
        Ok(val.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_table() -> InMemoryTable {
        InMemoryTable::new("Users")
            .with_column("Name", ForensicColumnType::Text, false)
            .with_column("Age", ForensicColumnType::I32, false)
            .with_row(vec![
                ForensicValue::Text("Alice".into()),
                ForensicValue::I64(42),
            ])
            .with_row(vec![
                ForensicValue::Text("Bob".into()),
                ForensicValue::I64(69),
            ])
    }

    #[test]
    fn list_tables_and_case_insensitive_lookup() {
        let db = InMemoryForensicDb::new().with_table(sample_table());
        assert_eq!(db.list_tables().unwrap(), vec!["Users".to_string()]);
        assert!(db.table("users").is_ok());
        assert!(db.table("USERS").is_ok());
        assert!(db.table("missing").is_err());
    }

    #[test]
    fn iterates_rows_and_reads_named_columns() {
        let db = InMemoryForensicDb::new().with_table(sample_table());
        let table = db.table("Users").unwrap();
        let mut rows = table.iter_rows().unwrap();

        assert!(rows.next().unwrap());
        assert_eq!(rows.read_named("name").unwrap(), ForensicValue::Text("Alice".into()));
        assert_eq!(rows.read_named("AGE").unwrap(), ForensicValue::I64(42));

        assert!(rows.next().unwrap());
        assert_eq!(rows.read_named("Name").unwrap(), ForensicValue::Text("Bob".into()));

        assert!(!rows.next().unwrap());
    }

    #[test]
    fn row_count_hint_matches_inserted_rows() {
        let table = sample_table();
        assert_eq!(table.row_count(), Some(2));
    }
}
