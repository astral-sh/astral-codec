/// Declare an enum whose unknown ZIP identifiers must round-trip losslessly.
macro_rules! wire_enum {
    (
        $(#[$attribute:meta])*
        $visibility:vis enum $name:ident($wire:ty) {
            $($(#[$doc:meta])* $variant:ident = $value:literal,)+
        }
    ) => {
        $(#[$attribute])*
        $visibility enum $name {
            $(
                $(#[$doc])*
                #[doc = concat!(" Wire value `", stringify!($value), "`.")]
                $variant,
            )+
            /// An unrecognized identifier and its wire value.
            Unknown($wire),
        }

        impl From<$wire> for $name {
            fn from(value: $wire) -> Self {
                match value {
                    $($value => Self::$variant,)+
                    other => Self::Unknown(other),
                }
            }
        }

        impl $name {
            pub(crate) const fn to_wire(self) -> $wire {
                match self {
                    $(Self::$variant => $value,)+
                    Self::Unknown(value) => value,
                }
            }
        }

        impl From<$name> for $wire {
            fn from(value: $name) -> Self {
                value.to_wire()
            }
        }
    };
}

pub(crate) use wire_enum;
