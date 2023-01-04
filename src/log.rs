use std::ops;

/// Log a prefixed message with a specific logger.
macro_rules! log_with {
    ($logger: ident, $prefix: literal, $fmt: literal) => {
        $logger!(concat!($prefix, $fmt))
    };
    ($logger: ident, $prefix: literal, $fmt: literal, $($args:expr),+) => {
        $logger!(concat!($prefix, $fmt), $($args),+)
    };
}

/// Log an info/success message to stdout, without trailing newline. Use `println!` to print the
/// end of the line.
#[allow(unused_macros)]
macro_rules! log {
    ($($args:expr),+) => {
        log_with!(print, "<allog> [+] ", $($args),+)
    };
}

/// Log an info/success message to stdout, with trailing newline.
macro_rules! logln {
    ($($args:expr),+) => {
        log_with!(println, "<allog> [+] ", $($args),+)
    };
}

/// Log an error message to stderr, with trailing newline.
macro_rules! elogln {
    ($($args:expr),+) => {
        log_with!(eprintln, "<allog> [!] ", $($args),+)
    };
}

pub(crate) struct LogMessage(Vec<String>);

impl LogMessage {
    #[allow(dead_code)]
    pub fn new() -> Self {
        LogMessage(Vec::new())
    }

    #[allow(dead_code)]
    pub fn push(&mut self, message: String) {
        self.0.push(message);
    }

    #[allow(dead_code)]
    pub fn log(self) {
        if self.0.len() > 0 {
            logln!("{}", &self.0[0]);
        }
        if self.0.len() > 1 {
            for msg in &self.0[1..] {
                logln!("  {}", &msg);
            }
        }
    }

    #[allow(dead_code)]
    pub fn elog(self) {
        if self.0.len() > 0 {
            elogln!("{}", &self.0[0]);
        }
        if self.0.len() > 1 {
            for msg in &self.0[1..] {
                elogln!("  {}", &msg);
            }
        }
    }
}

impl ops::Index<usize> for LogMessage {
    type Output = String;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl ops::IndexMut<usize> for LogMessage {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}
