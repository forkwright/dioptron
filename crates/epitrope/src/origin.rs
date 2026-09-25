//! Origins and origin patterns for target-scope authorization.
//!
//! This module only decides whether a target falls inside a grant's target
//! scope. It never fetches, resolves, or rewrites a target; the fetch stack
//! (behind the producer seam) parses the target again for acquisition.
//!
//! WHY a minimal parser instead of a URL crate: authorization needs the
//! scheme, host, and port and nothing else, and a parser that accepts less
//! than the WHATWG URL standard fails closed. Every construct where a
//! lenient parser and a strict one could disagree about the host is
//! refused here: userinfo (`@`), IPv6 literals, percent-encoding,
//! whitespace and control bytes (which WHATWG strips silently), missing or
//! extra slashes, trailing dots, non-ASCII hosts, and any host whose last
//! label reads as a number unless it is canonical dotted-decimal IPv4.
//! A refused target is denied, never widened.
//!
//! Pattern grammar: `[scheme "://"] host [":" port]`, where `scheme` is
//! `http` or `https` (omitted means both), `host` is `*` (any host), `*.`
//! followed by a domain (any proper subdomain of that domain, not the
//! domain itself), a domain, or dotted-decimal IPv4, and `port` omitted
//! means the scheme's default port.

use core::fmt;

use snafu::{OptionExt as _, ensure};

use crate::error::{Error, OriginSyntaxSnafu};

/// Longest accepted host, in bytes.
const MAX_HOST_LEN: usize = 253;
/// Longest accepted domain label, in bytes.
const MAX_LABEL_LEN: usize = 63;

/// A scheme the target scope can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Scheme {
    /// `http`, default port 80.
    Http,
    /// `https`, default port 443.
    Https,
}

impl Scheme {
    /// Both schemes, in declaration order.
    pub const ALL: [Self; 2] = [Self::Http, Self::Https];

    /// The scheme's default port.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    fn parse(text: &str) -> Result<Self, Error> {
        if text.eq_ignore_ascii_case("http") {
            Ok(Self::Http)
        } else if text.eq_ignore_ascii_case("https") {
            Ok(Self::Https)
        } else {
            OriginSyntaxSnafu {
                reason: "scheme is not http or https",
            }
            .fail()
        }
    }
}

/// A concrete host: a lowercase domain or an IPv4 address.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Host {
    Domain(String),
    Ipv4([u8; 4]),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain) => f.write_str(domain),
            Self::Ipv4([first, second, third, fourth]) => {
                write!(f, "{first}.{second}.{third}.{fourth}")
            }
        }
    }
}

/// The scheme, host, and effective port of a target.
///
/// # Examples
///
/// ```
/// use epitrope::Origin;
///
/// let origin = Origin::parse("https://Example.com/article?x=1")?;
/// assert_eq!(origin.to_string(), "https://example.com:443");
/// assert!(Origin::parse("https://user@example.com/").is_err());
/// # Ok::<(), epitrope::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Origin {
    scheme: Scheme,
    host: Host,
    port: u16,
}

impl Origin {
    /// Parses the origin of `target`, an absolute `http` or `https` URL.
    ///
    /// # Errors
    ///
    /// [`Error::OriginSyntax`] for any target outside the accepted subset
    /// (see the module documentation).
    pub fn parse(target: &str) -> Result<Self, Error> {
        ensure!(
            target.bytes().all(|b| b.is_ascii_graphic()),
            OriginSyntaxSnafu {
                reason: "target holds whitespace, control, or non-ASCII bytes"
            }
        );
        let (scheme, rest) = target.split_once("://").context(OriginSyntaxSnafu {
            reason: "target has no scheme separator",
        })?;
        let scheme = Scheme::parse(scheme)?;
        let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
        let (authority, _) = rest.split_at_checked(end).context(OriginSyntaxSnafu {
            reason: "authority boundary is not a character boundary",
        })?;
        let (host, port) = split_port(authority)?;
        let host = parse_host(host)?;
        Ok(Self {
            scheme,
            host,
            port: port.unwrap_or(scheme.default_port()),
        })
    }

    /// The scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The effective port: the explicit port, or the scheme's default.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        write!(f, "{scheme}://{}:{}", self.host, self.port)
    }
}

/// The host part of a pattern.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum HostPattern {
    Any,
    Exact(Host),
    Subdomains(String),
}

/// One origin pattern of a grant's target scope.
///
/// # Examples
///
/// ```
/// use epitrope::{Origin, OriginPattern};
///
/// let pattern = OriginPattern::parse("*.example.com")?;
/// assert!(pattern.matches(&Origin::parse("https://news.example.com/a")?));
/// assert!(!pattern.matches(&Origin::parse("https://example.com/a")?));
/// # Ok::<(), epitrope::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OriginPattern {
    scheme: Option<Scheme>,
    host: HostPattern,
    port: Option<u16>,
}

impl OriginPattern {
    /// Parses one pattern (grammar in the module documentation).
    ///
    /// # Errors
    ///
    /// [`Error::OriginSyntax`] for text outside the grammar.
    pub fn parse(text: &str) -> Result<Self, Error> {
        ensure!(
            text.bytes().all(|b| b.is_ascii_graphic()),
            OriginSyntaxSnafu {
                reason: "pattern holds whitespace, control, or non-ASCII bytes"
            }
        );
        let (scheme, authority) = match text.split_once("://") {
            Some((scheme, authority)) => (Some(Scheme::parse(scheme)?), authority),
            None => (None, text),
        };
        let (host, port) = split_port(authority)?;
        let host = if host == "*" {
            HostPattern::Any
        } else if let Some(domain) = host.strip_prefix("*.") {
            match parse_host(domain)? {
                Host::Domain(domain) => HostPattern::Subdomains(domain),
                Host::Ipv4(_) => {
                    return OriginSyntaxSnafu {
                        reason: "a wildcard cannot precede an address",
                    }
                    .fail();
                }
            }
        } else {
            HostPattern::Exact(parse_host(host)?)
        };
        Ok(Self { scheme, host, port })
    }

    /// Whether `origin` falls inside this pattern.
    #[must_use]
    pub fn matches(&self, origin: &Origin) -> bool {
        self.admits_scheme(origin.scheme)
            && self.port_for(origin.scheme) == origin.port
            && match &self.host {
                HostPattern::Any => true,
                HostPattern::Exact(host) => *host == origin.host,
                HostPattern::Subdomains(domain) => match &origin.host {
                    Host::Domain(name) => is_proper_subdomain(name, domain),
                    Host::Ipv4(_) => false,
                },
            }
    }

    /// Whether every origin `inner` matches is also matched by `self`.
    #[must_use]
    pub fn covers(&self, inner: &Self) -> bool {
        let schemes_covered = Scheme::ALL
            .iter()
            .filter(|&&scheme| inner.admits_scheme(scheme))
            .all(|&scheme| {
                self.admits_scheme(scheme) && self.port_for(scheme) == inner.port_for(scheme)
            });
        let host_covered = match (&self.host, &inner.host) {
            (HostPattern::Any, _) => true,
            (_, HostPattern::Any) | (HostPattern::Exact(_), HostPattern::Subdomains(_)) => false,
            (HostPattern::Exact(outer), HostPattern::Exact(host)) => outer == host,
            (HostPattern::Subdomains(outer), HostPattern::Exact(host)) => match host {
                Host::Domain(name) => is_proper_subdomain(name, outer),
                Host::Ipv4(_) => false,
            },
            (HostPattern::Subdomains(outer), HostPattern::Subdomains(domain)) => {
                domain == outer || is_proper_subdomain(domain, outer)
            }
        };
        schemes_covered && host_covered
    }

    fn admits_scheme(&self, scheme: Scheme) -> bool {
        self.scheme.is_none_or(|own| own == scheme)
    }

    /// The one port this pattern admits under `scheme`.
    fn port_for(&self, scheme: Scheme) -> u16 {
        self.port.unwrap_or(scheme.default_port())
    }
}

/// A grant's target scope: the origins a `Capture` may name.
///
/// An empty scope admits no target.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TargetScope(Vec<OriginPattern>);

impl TargetScope {
    /// Parses every pattern.
    ///
    /// # Errors
    ///
    /// [`Error::OriginSyntax`] when any pattern does not parse.
    pub fn parse<S: AsRef<str>>(patterns: &[S]) -> Result<Self, Error> {
        patterns
            .iter()
            .map(|pattern| OriginPattern::parse(pattern.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// The patterns.
    #[must_use]
    pub fn patterns(&self) -> &[OriginPattern] {
        &self.0
    }

    /// Whether some pattern matches `origin`.
    #[must_use]
    pub fn matches(&self, origin: &Origin) -> bool {
        self.0.iter().any(|pattern| pattern.matches(origin))
    }

    /// Whether every pattern of `inner` is covered by some pattern of
    /// `self`, so `inner` admits no origin `self` refuses.
    #[must_use]
    pub fn covers(&self, inner: &Self) -> bool {
        inner
            .0
            .iter()
            .all(|pattern| self.0.iter().any(|outer| outer.covers(pattern)))
    }
}

/// Splits `authority` into host text and optional port.
fn split_port(authority: &str) -> Result<(&str, Option<u16>), Error> {
    let Some((host, port)) = authority.split_once(':') else {
        return Ok((authority, None));
    };
    ensure!(
        !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
        OriginSyntaxSnafu {
            reason: "port is empty or not decimal"
        }
    );
    let port = port
        .bytes()
        .try_fold(0_u16, |acc, digit| {
            acc.checked_mul(10)?
                .checked_add(u16::from(digit.wrapping_sub(b'0')))
        })
        .context(OriginSyntaxSnafu {
            reason: "port is above 65535",
        })?;
    ensure!(
        port != 0,
        OriginSyntaxSnafu {
            reason: "port is 0"
        }
    );
    Ok((host, Some(port)))
}

/// Parses a host: canonical dotted-decimal IPv4 or an LDH domain.
fn parse_host(text: &str) -> Result<Host, Error> {
    ensure!(
        !text.is_empty() && text.len() <= MAX_HOST_LEN,
        OriginSyntaxSnafu {
            reason: "host is empty or too long"
        }
    );
    let labels: Vec<&str> = text.split('.').collect();
    let last = labels.last().copied().unwrap_or_default();
    if ends_in_number(last) {
        return parse_ipv4(&labels).map(Host::Ipv4);
    }
    for label in &labels {
        ensure!(
            is_ldh_label(label),
            OriginSyntaxSnafu {
                reason: "host label is empty, too long, or not letters, digits, and hyphens"
            }
        );
    }
    Ok(Host::Domain(text.to_ascii_lowercase()))
}

/// Whether a last label makes WHATWG parse the host as an IPv4 number.
fn ends_in_number(label: &str) -> bool {
    let decimal = !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit());
    let hex = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
        .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()));
    decimal || hex
}

/// Accepts exactly four canonical decimal octets.
fn parse_ipv4(labels: &[&str]) -> Result<[u8; 4], Error> {
    let [a, b, c, d] = labels else {
        return OriginSyntaxSnafu {
            reason: "numeric host is not four dotted octets",
        }
        .fail();
    };
    Ok([octet(a)?, octet(b)?, octet(c)?, octet(d)?])
}

fn octet(label: &str) -> Result<u8, Error> {
    let canonical = !label.is_empty()
        && label.len() <= 3
        && label.bytes().all(|b| b.is_ascii_digit())
        && (label == "0" || !label.starts_with('0'));
    ensure!(
        canonical,
        OriginSyntaxSnafu {
            reason: "numeric host octet is not canonical decimal"
        }
    );
    label.parse().ok().context(OriginSyntaxSnafu {
        reason: "numeric host octet is above 255",
    })
}

fn is_ldh_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Whether `name` is `domain` with at least one more label in front.
fn is_proper_subdomain(name: &str, domain: &str) -> bool {
    name.strip_suffix(domain)
        .and_then(|front| front.strip_suffix('.'))
        .is_some_and(|front| !front.is_empty())
}

#[cfg(test)]
mod tests;
