fn main() {
	if !std::env::var("LIBSQLITE3_FLAGS").unwrap_or_default().contains("-DSQLITE_MAX_ATTACHED=125") {
		println!("cargo:warning=LIBSQLITE3_FLAGS does not contain -DSQLITE_MAX_ATTACHED=125. Multi-tenant features may fail.");
	}
}

// vim: ts=4
