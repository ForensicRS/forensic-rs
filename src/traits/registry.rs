use crate::err::{ForensicResult, ForensicError};

#[derive(Clone, Copy)]
pub enum RegHiveKey {
    HkeyClassesRoot,
    HkeyCurrentConfig,
    HkeyCurrentUser,
    HkeyDynData,
    HkeyLocalMachine,
    KkeyPerformanceData,
    HkeyPerformanceNlstext,
    HkeyPerformanceText,
    HkeyUsers,
    Hkey(isize)
}

#[derive(Clone)]
pub enum RegValue {
    Binary(Vec<u8>),
    MultiSZ(String),
    ExpandSZ(String),
    SZ(String),
    DWord(u32),
    QWord(u64)
}

impl TryInto<String> for RegValue {
    type Error = ForensicError;
    fn try_into(self) -> Result<String, Self::Error> {
        match self {
            Self::MultiSZ(v) => Ok(v),
            Self::ExpandSZ(v) => Ok(v),
            Self::SZ(v) => Ok(v),
            _ => Err(ForensicError::CastError)
        }
    }
}

impl TryInto<u32> for RegValue {
    type Error = ForensicError;
    fn try_into(self) -> Result<u32, Self::Error> {
        match self {
            Self::DWord(v) => Ok(v),
            Self::QWord(v) => Ok(v as u32),
            _ => Err(ForensicError::CastError)
        }
    }
}

impl TryInto<u64> for RegValue {
    type Error = ForensicError;
    fn try_into(self) -> Result<u64, Self::Error> {
        match self {
            Self::DWord(v) => Ok(v as u64),
            Self::QWord(v) => Ok(v),
            _ => Err(ForensicError::CastError)
        }
    }
}

impl TryInto<Vec<u8>> for RegValue {
    type Error = ForensicError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Binary(v) => Ok(v),
            _ => Err(ForensicError::CastError)
        }
    }
}

/// It allows decoupling the registry access library from the analysis library.
pub trait RegistryReader {
    fn open_key(&mut self, hkey : RegHiveKey, key_name : &str) -> ForensicResult<RegHiveKey>;
    fn read_value(&self, hkey : RegHiveKey, value_name : &str) -> ForensicResult<RegValue>;
    fn enumerate_values(&self, hkey : RegHiveKey) -> ForensicResult<Vec<String>>;
    fn enumerate_keys(&self, hkey : RegHiveKey) -> ForensicResult<Vec<String>>;
    fn key_at(&self, hkey : RegHiveKey, pos : u32) -> ForensicResult<String>;
    fn value_at(&self, hkey : RegHiveKey, pos : u32) -> ForensicResult<String>;
}


#[cfg(test)]
mod reg_value {
    use super::RegValue;

    #[test]
    fn should_convert_using_try_into() {
        let _ : String = RegValue::SZ(format!("String RegValue")).try_into().expect("Must convert values");
        let _ : String = RegValue::MultiSZ(format!("String RegValue")).try_into().expect("Must convert values");
        let _ : String = RegValue::ExpandSZ(format!("String RegValue")).try_into().expect("Must convert values");

        let _ = TryInto::<u32>::try_into(RegValue::ExpandSZ(format!("String RegValue"))).expect_err("Should return error");
        let _ = TryInto::<u64>::try_into(RegValue::ExpandSZ(format!("String RegValue"))).expect_err("Should return error");
        let _ = TryInto::<Vec<u8>>::try_into(RegValue::ExpandSZ(format!("String RegValue"))).expect_err("Should return error");

        let _ : u32 = RegValue::DWord(123).try_into().expect("Must convert values");
        let _ : u64 = RegValue::DWord(123).try_into().expect("Must convert values");

        let _ = TryInto::<String>::try_into(RegValue::DWord(123)).expect_err("Should return error");
        let _ = TryInto::<Vec<u8>>::try_into(RegValue::DWord(123)).expect_err("Should return error");

        let _ : u32 = RegValue::QWord(123).clone().try_into().expect("Must convert values");
        let _ : u64 = RegValue::QWord(123).try_into().expect("Must convert values");

        let _ = TryInto::<String>::try_into(RegValue::QWord(123)).expect_err("Should return error");
        let _ = TryInto::<Vec<u8>>::try_into(RegValue::QWord(123)).expect_err("Should return error");

        let _ : Vec<u8> = RegValue::Binary((1..255).collect()).try_into().expect("Must convert values");
        let _ = TryInto::<u32>::try_into(RegValue::Binary((1..255).collect())).expect_err("Should return error");
        let _ = TryInto::<u32>::try_into(RegValue::Binary((1..255).collect())).expect_err("Should return error");
        let _ = TryInto::<u32>::try_into(RegValue::Binary((1..255).collect())).expect_err("Should return error");
    }
}