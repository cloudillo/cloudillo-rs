pub trait AuthAdapter {
    fn init() -> Result<Box<str>, Box<dyn std::error::Error>>;
}
