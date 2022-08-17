use anyhow::{anyhow, Result};

// Extract a key from the auxiliary vector starting the search from
// the environment pointer
pub fn getauxval(
	envp: *const *const u8,
	key: usize,
) -> Result<usize> {
	// First, find the end of the environment variables as denoted by
	// a zero word
	let mut ptr_idx = 0;
	while unsafe { *envp.add(ptr_idx) } != (0 as *const u8) {
		ptr_idx += 1;
	}
	ptr_idx += 1;
	// Next, go through each 2-word auxv entry searching for the key
	let mut value;
	'auxp_iter: loop {
		let itr_key = unsafe { *envp.add(ptr_idx) as usize };
		value = unsafe { *envp.add(ptr_idx + 1) as usize };
		// We found the match
		if itr_key == key {
			break 'auxp_iter;
		}
		// We reached the end
		else if libc::AT_NULL as usize == itr_key {
			return Err(anyhow!(
				"Unable to find key in auxiliary vector."
			));
		}
		ptr_idx += 2;
	}
	Ok(value)
}
