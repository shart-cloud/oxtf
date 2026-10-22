use super::{Record, ResolveError};
use std::collections::HashMap;

use serde::de::{DeserializeSeed, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tf_limits::input::InputBudget;

pub(super) fn records(
    text: &str,
    budget: &InputBudget,
) -> Result<HashMap<String, Record>, ResolveError> {
    let mut decoder = serde_json::Deserializer::from_str(text);
    let mut seed = Manifest {
        budget,
        duplicate: false,
    };
    let result = (&mut seed).deserialize(&mut decoder).and_then(|records| {
        decoder.end()?;
        Ok(records)
    });
    result.map_err(|error| {
        if let Some(error) = budget.exhaustion() {
            ResolveError::Storage(error)
        } else if seed.duplicate {
            ResolveError::Invalid("duplicate module key in installed module manifest".into())
        } else {
            ResolveError::Invalid(format!(
                "invalid installed module manifest at line {}, column {}",
                error.line(),
                error.column()
            ))
        }
    })
}

struct Manifest<'a> {
    budget: &'a InputBudget,
    duplicate: bool,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum Field {
    Modules,
    #[serde(other)]
    Other,
}

impl<'de> DeserializeSeed<'de> for &mut Manifest<'_> {
    type Value = HashMap<String, Record>;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_struct("Snapshot", &["Modules"], self)
    }
}

impl<'de> Visitor<'de> for &mut Manifest<'_> {
    type Value = HashMap<String, Record>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an installed module manifest")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut records = None;
        while let Some(field) = map.next_key::<Field>()? {
            match field {
                Field::Modules => {
                    if records.is_some() {
                        return Err(M::Error::duplicate_field("Modules"));
                    }
                    records = Some(map.next_value_seed(Modules(self))?);
                }
                Field::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        records.ok_or_else(|| M::Error::missing_field("Modules"))
    }
}

struct Modules<'a, 'b>(&'a mut Manifest<'b>);

impl<'de> DeserializeSeed<'de> for Modules<'_, '_> {
    type Value = HashMap<String, Record>;

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Modules<'_, '_> {
    type Value = HashMap<String, Record>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("installed module records")
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut records = HashMap::new();
        while seq
            .next_element_seed(Entry {
                manifest: self.0,
                records: &mut records,
            })?
            .is_some()
        {}
        Ok(records)
    }
}

struct Entry<'a, 'b> {
    manifest: &'a mut Manifest<'b>,
    records: &'a mut HashMap<String, Record>,
}

impl<'de> DeserializeSeed<'de> for Entry<'_, '_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        // Called only for an actual array element. Reserve before decoding its fields;
        // neither an unbounded intermediate Vec nor a second key String is needed.
        crate::model_budget::hash_slot(self.records, self.manifest.budget)
            .map_err(|_| D::Error::custom("installed module storage exhausted"))?;
        let mut record = Record::deserialize(decoder)?;
        let key = std::mem::take(&mut record.key);
        if self.records.contains_key(&key) {
            self.manifest.duplicate = true;
            return Err(D::Error::custom("duplicate module key"));
        }
        let previous = self.records.insert(key, record);
        assert!(previous.is_none());
        Ok(())
    }
}
