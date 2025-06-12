use chrono::Utc;

/// Removes '0x' prefix from hexadecimal strings if present
pub(crate) fn hex_fix(word: &str) -> String {
    if word.starts_with("0x") {
        word[2..].to_string()
    } else {
        word.to_string()
    }
}

/// Converts a string to its hexadecimal representation without '0x' prefix
pub(crate) fn string_to_hex(str: &str) -> String {
    hex::encode(str.as_bytes())
}

/// Converts a hexadecimal string to a regular string
pub(crate) fn hex_to_string(hex: &str) -> Result<String, hex::FromHexError> {
    let hex = hex_fix(hex);
    let bytes = hex::decode(hex)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Returns a formatted timestamp in the format "YYYY:MM:DD-HH:mm:ss"
pub(crate) fn get_formatted_timestamp() -> String {
    let now = Utc::now();
    format!(
        "{:04}:{:02}:{:02}-{:02}:{:02}:{:02}",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
} 