//! Builder for mint requests. Validates raw input into domain values; relative
//! expirations are resolved by the broker against its `Clock`.

use crate::domain::*;

#[derive(Clone, Debug)]
pub(crate) enum Pending {
    Fixed(Caveat),
    ExpiresIn(u64),
}

#[derive(Clone, Debug)]
pub struct TokenBuilder {
    pub(crate) subject: Result<Subject, DomainError>,
    pub(crate) caveats: Vec<Pending>,
    pub(crate) error: Option<DomainError>,
}

impl TokenBuilder {
    pub fn new(subject: &str) -> Self {
        Self {
            subject: Subject::parse(subject),
            caveats: Vec::new(),
            error: None,
        }
    }

    fn push(mut self, c: Result<Caveat, DomainError>) -> Self {
        match c {
            Ok(c) => self.caveats.push(Pending::Fixed(c)),
            Err(e) => {
                self.error.get_or_insert(e);
            }
        }
        self
    }

    pub fn expires_at(self, unix: u64) -> Self {
        self.push(Ok(Caveat::ExpiresAt(unix)))
    }

    pub fn expires_in(mut self, secs: u64) -> Self {
        self.caveats.push(Pending::ExpiresIn(secs));
        self
    }

    pub fn not_before(self, unix: u64) -> Self {
        self.push(Ok(Caveat::NotBefore(unix)))
    }

    pub fn audience(self, a: &str) -> Self {
        self.push(Audience::parse(a).map(Caveat::Audience))
    }

    pub fn path_prefix(self, p: &str) -> Self {
        self.push(ResourcePath::parse(p).map(Caveat::PathPrefix))
    }

    pub fn actions(self, actions: &[&str]) -> Self {
        let parsed: Result<Vec<Action>, DomainError> =
            actions.iter().map(|a| Action::parse(a)).collect();
        self.push(parsed.and_then(Caveat::actions))
    }

    pub(crate) fn resolve(self, now: u64) -> Result<(Subject, Vec<Caveat>), DomainError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let subject = self.subject?;
        let caveats = self
            .caveats
            .into_iter()
            .map(|p| match p {
                Pending::Fixed(c) => c,
                Pending::ExpiresIn(s) => Caveat::ExpiresAt(now.saturating_add(s)),
            })
            .collect::<Vec<_>>();
        if caveats.len() > MAX_CAVEATS {
            return Err(DomainError::TooManyCaveats);
        }
        Ok((subject, caveats))
    }
}
