//! Join owned adapter tasks without turning a panic into a missing observation.
use tokio::task::{JoinError, JoinSet};

pub async fn collect<T: 'static>(
    mut tasks: JoinSet<T>,
) -> Result<Vec<T>, JoinError> {
    let mut values = Vec::new();
    while let Some(result) = tasks.join_next().await {
        values.push(result?);
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panicking_probe_is_an_error_instead_of_an_incomplete_success() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async { 1 });
        tasks.spawn(async { panic!("probe bug") });

        let error = collect(tasks).await.unwrap_err();

        assert!(error.is_panic());
    }
}
