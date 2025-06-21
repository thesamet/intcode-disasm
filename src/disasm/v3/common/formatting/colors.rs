use colored::Color;

// Added Enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticColor {
    Keyword,
    Variable,
    Operator,
    Type,
    Constant,
    LowPrio, // For punctuation, comments, etc.
    Function,
    // Add more semantic types if needed
}

impl SemanticColor {
    pub fn to_css_class(&self) -> &'static str {
        match self {
            SemanticColor::Keyword => "keyword",
            SemanticColor::Variable => "variable", 
            SemanticColor::Operator => "operator",
            SemanticColor::Type => "type",
            SemanticColor::Constant => "constant",
            SemanticColor::LowPrio => "low-prio",
            SemanticColor::Function => "function",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Colors {
    pub keyword: Color,
    pub variable: Color,

    pub op_color: Color,
    pub type_color: Color,
    pub const_color: Color,

    pub low_prio: Color,

    pub function: Color,

    pub bg_color: Color,
}

impl Colors {
    // Helper to get the actual color based on semantic type
    pub fn get_color(&self, semantic: SemanticColor) -> Color {
        match semantic {
            SemanticColor::Keyword => self.keyword,
            SemanticColor::Variable => self.variable,
            SemanticColor::Operator => self.op_color,
            SemanticColor::Type => self.type_color,
            SemanticColor::Constant => self.const_color,
            SemanticColor::LowPrio => self.low_prio,
            SemanticColor::Function => self.function,
        }
    }

    pub fn default_color_theme() -> Colors {
        // A nice dark theme with pink accent colors
        Colors {
            keyword: Color::TrueColor {
                r: 253,
                g: 104,
                b: 131,
            }, // keyword - pink
            variable: Color::TrueColor {
                r: 255,
                g: 241,
                b: 243,
            }, // variable - light pink
            op_color: Color::TrueColor {
                r: 253,
                g: 104,
                b: 131,
            }, // op_color - pink
            type_color: Color::TrueColor {
                r: 133,
                g: 218,
                b: 204,
            }, // type_color - aqua
            const_color: Color::TrueColor {
                r: 0xa8,
                g: 0xa9,
                b: 0xeb,
            }, // const_color - lavender
            low_prio: Color::TrueColor {
                r: 0x94,
                g: 0x8a,
                b: 0x8b,
            }, // low_prio - muted gray
            function: Color::TrueColor {
                r: 173,
                g: 218,
                b: 120,
            }, // function - lime green
            bg_color: Color::TrueColor {
                r: 44,
                g: 37,
                b: 37,
            }, // bg_color - dark gray
        }
    }

    pub fn high_contrast_theme() -> Colors {
        // High contrast theme for better readability
        Colors {
            keyword: Color::BrightYellow,
            variable: Color::BrightWhite,
            op_color: Color::BrightRed,
            type_color: Color::BrightCyan,
            const_color: Color::BrightGreen,
            low_prio: Color::BrightBlack,
            function: Color::BrightBlue,
            bg_color: Color::Black,
        }
    }

    pub fn light_theme() -> Colors {
        // Light theme for those who prefer light backgrounds
        Colors {
            keyword: Color::Blue,
            variable: Color::Black,
            op_color: Color::Red,
            type_color: Color::Green,
            const_color: Color::Magenta,
            low_prio: Color::BrightBlack,
            function: Color::Cyan,
            bg_color: Color::White,
        }
    }

    pub fn monochrome_theme() -> Colors {
        // Simple monochrome theme for terminals with limited color support
        Colors {
            keyword: Color::White,
            variable: Color::White,
            op_color: Color::White,
            type_color: Color::White,
            const_color: Color::White,
            low_prio: Color::White,
            function: Color::White,
            bg_color: Color::Black,
        }
    }

    pub fn blue_accent_theme() -> Colors {
        // A dark theme with blue accents
        Colors {
            keyword: Color::TrueColor {
                r: 97,
                g: 175,
                b: 239,
            }, // keyword - bright blue
            variable: Color::TrueColor {
                r: 224,
                g: 224,
                b: 224,
            }, // variable - light gray
            op_color: Color::TrueColor {
                r: 97,
                g: 175,
                b: 239,
            }, // op_color - bright blue
            type_color: Color::TrueColor {
                r: 152,
                g: 195,
                b: 121,
            }, // type_color - green
            const_color: Color::TrueColor {
                r: 209,
                g: 154,
                b: 102,
            }, // const_color - orange
            low_prio: Color::TrueColor {
                r: 92,
                g: 99,
                b: 112,
            }, // low_prio - gray
            function: Color::TrueColor {
                r: 198,
                g: 120,
                b: 221,
            }, // function - purple
            bg_color: Color::TrueColor {
                r: 40,
                g: 44,
                b: 52,
            }, // bg_color - dark blue-gray
        }
    }

    pub fn tokyo_night_theme() -> Colors {
        // Tokyo Night theme - dark blue background with vibrant accents
        Colors {
            keyword: Color::TrueColor {
                r: 0xbb,
                g: 0x9a,
                b: 0xf7,
            }, // keyword - purple (official)
            variable: Color::TrueColor {
                r: 0xa9,
                g: 0xb1,
                b: 0xd6,
            }, // variable - lavender (official)
            op_color: Color::TrueColor {
                r: 0xff,
                g: 0x9e,
                b: 0x64,
            }, // op_color - orange (official)
            type_color: Color::TrueColor {
                r: 0x9e,
                g: 0xcc,
                b: 0xed,
            }, // type_color - light blue (official)
            const_color: Color::TrueColor {
                r: 0xff,
                g: 0x9e,
                b: 0x64,
            }, // const_color - orange (official)
            low_prio: Color::TrueColor {
                r: 0x56,
                g: 0x5f,
                b: 0x89,
            }, // low_prio - gray-blue (official)
            function: Color::TrueColor {
                r: 0x7a,
                g: 0xa2,
                b: 0xf7,
            }, // function - blue (official)
            bg_color: Color::TrueColor {
                r: 0x1a,
                g: 0x1b,
                b: 0x26,
            }, // bg_color - dark blue-black (official Tokyo Night color)
        }
    }

    pub fn tokyo_night_storm_theme() -> Colors {
        // Tokyo Night Storm theme - slightly lighter variation of Tokyo Night
        Colors {
            keyword: Color::TrueColor {
                r: 0xbb,
                g: 0x9a,
                b: 0xf7,
            }, // keyword - purple
            variable: Color::TrueColor {
                r: 0xa9,
                g: 0xb1,
                b: 0xd6,
            }, // variable - lavender
            op_color: Color::TrueColor {
                r: 0xff,
                g: 0x9e,
                b: 0x64,
            }, // op_color - orange
            type_color: Color::TrueColor {
                r: 0x9e,
                g: 0xcc,
                b: 0xed,
            }, // type_color - light blue
            const_color: Color::TrueColor {
                r: 0xff,
                g: 0x9e,
                b: 0x64,
            }, // const_color - orange
            low_prio: Color::TrueColor {
                r: 0x56,
                g: 0x5f,
                b: 0x89,
            }, // low_prio - gray-blue
            function: Color::TrueColor {
                r: 0x7a,
                g: 0xa2,
                b: 0xf7,
            }, // function - blue
            bg_color: Color::TrueColor {
                r: 0x24,
                g: 0x28,
                b: 0x3b,
            }, // bg_color - medium blue-black (official Tokyo Night Storm color)
        }
    }

    pub fn catppuccin_mocha_theme() -> Colors {
        // Catppuccin Mocha theme - dark and cozy
        Colors {
            keyword: Color::TrueColor {
                r: 0xf3,
                g: 0x8b,
                b: 0xa8,
            }, // keyword - pink (official)
            variable: Color::TrueColor {
                r: 0xcd,
                g: 0xd6,
                b: 0xf4,
            }, // variable - lavender (official)
            op_color: Color::TrueColor {
                r: 0xed,
                g: 0x8a,
                b: 0x96,
            }, // op_color - red (official)
            type_color: Color::TrueColor {
                r: 0xa6,
                g: 0xe3,
                b: 0xa1,
            }, // type_color - green (official)
            const_color: Color::TrueColor {
                r: 0xf9,
                g: 0xe2,
                b: 0xaf,
            }, // const_color - yellow (official)
            low_prio: Color::TrueColor {
                r: 0x6c,
                g: 0x7c,
                b: 0x94,
            }, // low_prio - gray (official)
            function: Color::TrueColor {
                r: 0x89,
                g: 0xb4,
                b: 0xfa,
            }, // function - blue (official)
            bg_color: Color::TrueColor {
                r: 0x1e,
                g: 0x1e,
                b: 0x2e,
            }, // bg_color - dark blue (official Catppuccin Mocha color)
        }
    }

    pub fn catppuccin_macchiato_theme() -> Colors {
        // Catppuccin Macchiato theme - medium dark and cozy
        Colors {
            keyword: Color::TrueColor {
                r: 0xf4,
                g: 0x8f,
                b: 0xb1,
            }, // keyword - pink
            variable: Color::TrueColor {
                r: 0xca,
                g: 0xd3,
                b: 0xf5,
            }, // variable - lavender
            op_color: Color::TrueColor {
                r: 0xed,
                g: 0x8a,
                b: 0x96,
            }, // op_color - red
            type_color: Color::TrueColor {
                r: 0xa6,
                g: 0xda,
                b: 0x95,
            }, // type_color - green
            const_color: Color::TrueColor {
                r: 0xee,
                g: 0xd4,
                b: 0x9f,
            }, // const_color - yellow
            low_prio: Color::TrueColor {
                r: 0x5b,
                g: 0x6c,
                b: 0x8c,
            }, // low_prio - gray
            function: Color::TrueColor {
                r: 0x8a,
                g: 0xaa,
                b: 0xed,
            }, // function - blue
            bg_color: Color::TrueColor {
                r: 0x24,
                g: 0x27,
                b: 0x3a,
            }, // bg_color - medium dark blue (official Catppuccin Macchiato color)
        }
    }

    pub fn catppuccin_frappe_theme() -> Colors {
        // Catppuccin Frappe theme - balanced and cozy
        Colors {
            keyword: Color::TrueColor {
                r: 0xf4,
                g: 0x8f,
                b: 0xb1,
            }, // keyword - pink
            variable: Color::TrueColor {
                r: 0xc6,
                g: 0xd0,
                b: 0xf5,
            }, // variable - lavender
            op_color: Color::TrueColor {
                r: 0xe7,
                g: 0x8c,
                b: 0x8c,
            }, // op_color - red
            type_color: Color::TrueColor {
                r: 0xa6,
                g: 0xd1,
                b: 0x89,
            }, // type_color - green
            const_color: Color::TrueColor {
                r: 0xe5,
                g: 0xc8,
                b: 0x90,
            }, // const_color - yellow
            low_prio: Color::TrueColor {
                r: 0x62,
                g: 0x73,
                b: 0x8c,
            }, // low_prio - gray
            function: Color::TrueColor {
                r: 0x8c,
                g: 0xaa,
                b: 0xee,
            }, // function - blue
            bg_color: Color::TrueColor {
                r: 0x30,
                g: 0x34,
                b: 0x46,
            }, // bg_color - medium blue (official Catppuccin Frappe color)
        }
    }

    pub fn catppuccin_latte_theme() -> Colors {
        // Catppuccin Latte theme - light and cozy
        Colors {
            keyword: Color::TrueColor {
                r: 0xd2,
                g: 0x0f,
                b: 0x39,
            }, // keyword - pink (official)
            variable: Color::TrueColor {
                r: 0x4c,
                g: 0x4f,
                b: 0x69,
            }, // variable - dark lavender (official)
            op_color: Color::TrueColor {
                r: 0xd2,
                g: 0x0f,
                b: 0x39,
            }, // op_color - red (official)
            type_color: Color::TrueColor {
                r: 0x40,
                g: 0xa0,
                b: 0x2b,
            }, // type_color - green (official)
            const_color: Color::TrueColor {
                r: 0xdf,
                g: 0x8e,
                b: 0x1d,
            }, // const_color - yellow (official)
            low_prio: Color::TrueColor {
                r: 0x6c,
                g: 0x6f,
                b: 0x85,
            }, // low_prio - gray (official)
            function: Color::TrueColor {
                r: 0x1e,
                g: 0x66,
                b: 0xf5,
            }, // function - blue (official)
            bg_color: Color::TrueColor {
                r: 0xef,
                g: 0xf1,
                b: 0xf5,
            }, // bg_color - white (official Catppuccin Latte color)
        }
    }

    pub fn dracula_theme() -> Colors {
        // Dracula theme - dark theme with vibrant colors
        Colors {
            keyword: Color::TrueColor {
                r: 0xff,
                g: 0x79,
                b: 0xc6,
            }, // keyword - pink
            variable: Color::TrueColor {
                r: 0xf8,
                g: 0xf8,
                b: 0xf2,
            }, // variable - off white
            op_color: Color::TrueColor {
                r: 0xff,
                g: 0x79,
                b: 0xc6,
            }, // op_color - pink
            type_color: Color::TrueColor {
                r: 0x8b,
                g: 0xe9,
                b: 0xfd,
            }, // type_color - cyan
            const_color: Color::TrueColor {
                r: 0xf1,
                g: 0xfa,
                b: 0x8c,
            }, // const_color - yellow
            low_prio: Color::TrueColor {
                r: 0x62,
                g: 0x72,
                b: 0xa4,
            }, // low_prio - comment blue
            function: Color::TrueColor {
                r: 0x50,
                g: 0xfa,
                b: 0x7b,
            }, // function - green
            bg_color: Color::TrueColor {
                r: 0x28,
                g: 0x2a,
                b: 0x36,
            }, // bg_color - dark background
        }
    }

    pub fn nord_theme() -> Colors {
        // Nord theme - arctic, north-bluish color palette
        Colors {
            keyword: Color::TrueColor {
                r: 0x81,
                g: 0xa1,
                b: 0xc1,
            }, // keyword - frost blue
            variable: Color::TrueColor {
                r: 0xd8,
                g: 0xde,
                b: 0xe9,
            }, // variable - snow storm 1
            op_color: Color::TrueColor {
                r: 0x81,
                g: 0xa1,
                b: 0xc1,
            }, // op_color - frost blue
            type_color: Color::TrueColor {
                r: 0x8f,
                g: 0xbc,
                b: 0xbb,
            }, // type_color - frost cyan
            const_color: Color::TrueColor {
                r: 0xeb,
                g: 0xcb,
                b: 0x8b,
            }, // const_color - aurora yellow
            low_prio: Color::TrueColor {
                r: 0x4c,
                g: 0x56,
                b: 0x6a,
            }, // low_prio - polar night 4
            function: Color::TrueColor {
                r: 0xa3,
                g: 0xbe,
                b: 0x8c,
            }, // function - aurora green
            bg_color: Color::TrueColor {
                r: 0x2e,
                g: 0x34,
                b: 0x40,
            }, // bg_color - polar night 1
        }
    }

    pub fn solarized_dark_theme() -> Colors {
        // Solarized Dark theme - careful color selection based on fixed color wheel relationships
        Colors {
            keyword: Color::TrueColor {
                r: 0x26,
                g: 0x8b,
                b: 0xd2,
            }, // keyword - blue
            variable: Color::TrueColor {
                r: 0x83,
                g: 0x94,
                b: 0x96,
            }, // variable - base0
            op_color: Color::TrueColor {
                r: 0x2a,
                g: 0xa1,
                b: 0x98,
            }, // op_color - cyan
            type_color: Color::TrueColor {
                r: 0x6c,
                g: 0x71,
                b: 0xc4,
            }, // type_color - violet
            const_color: Color::TrueColor {
                r: 0xb5,
                g: 0x89,
                b: 0x00,
            }, // const_color - yellow
            low_prio: Color::TrueColor {
                r: 0x58,
                g: 0x6e,
                b: 0x75,
            }, // low_prio - base01
            function: Color::TrueColor {
                r: 0x85,
                g: 0x99,
                b: 0x00,
            }, // function - green
            bg_color: Color::TrueColor {
                r: 0x00,
                g: 0x2b,
                b: 0x36,
            }, // bg_color - base03
        }
    }

    pub fn onedark_theme() -> Colors {
        // One Dark Pro - Atom's iconic One Dark theme
        Colors {
            keyword: Color::TrueColor {
                r: 0xc6,
                g: 0x78,
                b: 0xdd,
            }, // keyword - purple
            variable: Color::TrueColor {
                r: 0xab,
                g: 0xb2,
                b: 0xbf,
            }, // variable - foreground
            op_color: Color::TrueColor {
                r: 0xc6,
                g: 0x78,
                b: 0xdd,
            }, // op_color - purple
            type_color: Color::TrueColor {
                r: 0x56,
                g: 0xb6,
                b: 0xc2,
            }, // type_color - cyan
            const_color: Color::TrueColor {
                r: 0xe5,
                g: 0xc0,
                b: 0x7b,
            }, // const_color - yellow
            low_prio: Color::TrueColor {
                r: 0x54,
                g: 0x58,
                b: 0x62,
            }, // low_prio - gutter gray
            function: Color::TrueColor {
                r: 0x61,
                g: 0xaf,
                b: 0xef,
            }, // function - blue
            bg_color: Color::TrueColor {
                r: 0x28,
                g: 0x2c,
                b: 0x34,
            }, // bg_color - background
        }
    }

    pub fn github_dark_theme() -> Colors {
        // GitHub Dark theme - official GitHub dark theme colors
        Colors {
            keyword: Color::TrueColor {
                r: 0xbc,
                g: 0x8c,
                b: 0xff,
            }, // keyword - purple
            variable: Color::TrueColor {
                r: 0xc9,
                g: 0xd1,
                b: 0xd9,
            }, // variable - fg-default
            op_color: Color::TrueColor {
                r: 0x79,
                g: 0xc0,
                b: 0xff,
            }, // op_color - bright blue
            type_color: Color::TrueColor {
                r: 0x79,
                g: 0xc0,
                b: 0xff,
            }, // type_color - bright blue
            const_color: Color::TrueColor {
                r: 0xe3,
                g: 0xb3,
                b: 0x41,
            }, // const_color - yellow
            low_prio: Color::TrueColor {
                r: 0x8b,
                g: 0x94,
                b: 0x9e,
            }, // low_prio - gray
            function: Color::TrueColor {
                r: 0x3f,
                g: 0xb9,
                b: 0x50,
            }, // function - green
            bg_color: Color::TrueColor {
                r: 0x0d,
                g: 0x11,
                b: 0x17,
            }, // bg_color - dark background
        }
    }
}

impl Default for Colors {
    fn default() -> Self {
        Self::default_color_theme()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ThemeInfo {
    pub name: &'static str,
    pub description: &'static str,
}

impl Colors {
    pub const THEMES: &'static [ThemeInfo] = &[
        ThemeInfo {
            name: "default",
            description: "Default dark theme with pink accent colors",
        },
        ThemeInfo {
            name: "high-contrast",
            description: "High contrast theme for better readability",
        },
        ThemeInfo {
            name: "light",
            description: "Light theme for those who prefer light backgrounds",
        },
        ThemeInfo {
            name: "monochrome",
            description: "Simple monochrome theme for limited color support",
        },
        ThemeInfo {
            name: "blue",
            description: "A dark theme with blue accents",
        },
        ThemeInfo {
            name: "tokyo-night",
            description: "Tokyo Night theme - dark blue background with vibrant accents",
        },
        ThemeInfo {
            name: "tokyo-night-storm",
            description: "Tokyo Night Storm theme - slightly lighter variation of Tokyo Night",
        },
        ThemeInfo {
            name: "catppuccin-mocha",
            description: "Catppuccin Mocha theme - dark and cozy",
        },
        ThemeInfo {
            name: "catppuccin-macchiato",
            description: "Catppuccin Macchiato theme - medium dark and cozy",
        },
        ThemeInfo {
            name: "catppuccin-frappe",
            description: "Catppuccin Frappe theme - balanced and cozy",
        },
        ThemeInfo {
            name: "catppuccin-latte",
            description: "Catppuccin Latte theme - light and cozy",
        },
        ThemeInfo {
            name: "dracula",
            description: "Dracula theme - dark theme with vibrant colors",
        },
        ThemeInfo {
            name: "nord",
            description: "Nord theme - arctic, north-bluish color palette",
        },
        ThemeInfo {
            name: "solarized-dark",
            description: "Solarized Dark - precision colors with careful color selection",
        },
        ThemeInfo {
            name: "onedark",
            description: "One Dark Pro - Atom's iconic One Dark theme",
        },
        ThemeInfo {
            name: "github-dark",
            description: "GitHub Dark - official GitHub dark theme colors",
        },
    ];

    // Get a list of all available theme names
    pub fn get_theme_names() -> Vec<&'static str> {
        Self::THEMES.iter().map(|info| info.name).collect()
    }

    // Get theme descriptions for display
    pub fn get_theme_descriptions() -> Vec<(&'static str, &'static str)> {
        Self::THEMES
            .iter()
            .map(|info| (info.name, info.description))
            .collect()
    }

    // Convenience method to get a color theme by name
    pub fn get_theme_by_name(name: &str) -> Option<Self> {
        match name {
            "default" => Some(Self::default_color_theme()),
            "high-contrast" => Some(Self::high_contrast_theme()),
            "light" => Some(Self::light_theme()),
            "monochrome" => Some(Self::monochrome_theme()),
            "blue" => Some(Self::blue_accent_theme()),
            "tokyo-night" => Some(Self::tokyo_night_theme()),
            "tokyo-night-storm" => Some(Self::tokyo_night_storm_theme()),
            "catppuccin-mocha" => Some(Self::catppuccin_mocha_theme()),
            "catppuccin-macchiato" => Some(Self::catppuccin_macchiato_theme()),
            "catppuccin-frappe" => Some(Self::catppuccin_frappe_theme()),
            "catppuccin-latte" => Some(Self::catppuccin_latte_theme()),
            "dracula" => Some(Self::dracula_theme()),
            "nord" => Some(Self::nord_theme()),
            "solarized-dark" => Some(Self::solarized_dark_theme()),
            "onedark" => Some(Self::onedark_theme()),
            "github-dark" => Some(Self::github_dark_theme()),
            _ => None,
        }
    }
}
