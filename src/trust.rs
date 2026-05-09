use std::error::Error;
use std::os::unix::fs::MetadataExt;

pub async fn is_trusted_binary(path: &str) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let metadata = match tokio::fs::metadata(path).await {
        Ok(metadata) => metadata,
        Err(_) => return Ok(false),
    };

    if !metadata.file_type().is_file() {
        return Ok(false);
    }

    if metadata.uid() != 0 {
        return Ok(false);
    }

    if metadata.mode() & 0o022 != 0 {
        return Ok(false);
    }

    Ok(true)
}
