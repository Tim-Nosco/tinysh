#![allow(unused_macros, unused_imports)]

use thiserror::Error;

// A little trick to make it so the debug printing doesn't output in
// the release
macro_rules! debug {
    ($($x:tt)*) => {
        {
            #[cfg(debug_assertions)]
            {
                println!($($x)*)
            }
            #[cfg(not(debug_assertions))]
            {
                ($($x)*)
            }
        }
    }
}
pub(crate) use debug;

#[derive(Error, Debug)]
pub enum CopyError {
	#[error("The two types differ in length.")]
	Length,
}

// This function works around a panic condition in copy_from_slice by
// checking the length first
pub fn copy_from_slice(
	dst: &mut [u8],
	src: &[u8],
) -> Result<(), CopyError> {
	if dst.len() == src.len() {
		dst.copy_from_slice(&src);
		Ok(())
	} else {
		Err(CopyError::Length)
	}
}
