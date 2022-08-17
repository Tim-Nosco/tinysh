#![allow(unused_macros, unused_imports)]
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
