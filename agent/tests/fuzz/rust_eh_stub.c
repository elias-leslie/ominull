/* Without LTO the prebuilt Rust core still names this; panics abort, so it never runs. */
void rust_eh_personality(void);
void rust_eh_personality(void) {}
