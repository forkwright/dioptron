//! Declaration macro for the contract's fieldless vocabulary enums.

/// Declares a fieldless, non-exhaustive contract enum with a stable name per
/// variant.
///
/// WHY: the fixtures and the audit log refer to variants by name, so every
/// vocabulary enum carries the same `ALL`, `name`, `from_name`, and
/// `Display` surface, defined once here.
macro_rules! named_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $text:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord,
            rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
        )]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// Every variant this contract version defines, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The contract name of this variant, as the fixtures and audit
            /// records spell it.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }

            /// Parses a contract name. Returns `None` for a name this contract
            /// version does not define.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|variant| variant.name() == name)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

pub(crate) use named_enum;
