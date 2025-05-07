use colored::{Color, Colorize};

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
    pub fn new(
        keyword: Color,
        variable: Color,
        op_color: Color,
        type_color: Color,
        const_color: Color,
        low_prio: Color,
        function: Color,
        bg_color: Color,
    ) -> Self {
        Colors {
            keyword,
            variable,
            op_color,
            type_color,
            const_color,
            low_prio,
            function,
            bg_color,
        }
    }

    pub fn open_paren(&self) -> String {
        "(".color(self.low_prio).to_string()
    }
    pub fn close_paren(&self) -> String {
        ")".color(self.low_prio).to_string()
    }
    pub fn open_brace(&self) -> String {
        "{".color(self.low_prio).to_string()
    }
    pub fn close_brace(&self) -> String {
        "}".color(self.low_prio).to_string()
    }
    pub fn colon(&self) -> String {
        ":".color(self.low_prio).to_string()
    }
    pub fn comma(&self) -> String {
        ", ".color(self.low_prio).to_string()
    }
    pub fn eq(&self) -> String {
        "=".color(self.op_color).to_string()
    }
    pub fn semicolon(&self) -> String {
        ";".color(self.low_prio).to_string()
    }
    pub fn ampersand(&self) -> String {
        "&".color(self.op_color).to_string()
    }

    pub fn default_color_theme() -> Colors {
        // A nice dark theme with pink accent colors
        Colors::new(
            Color::TrueColor {
                r: 253,
                g: 104,
                b: 131,
            }, // keyword - pink
            Color::TrueColor {
                r: 255,
                g: 241,
                b: 243,
            }, // variable - light pink
            Color::TrueColor {
                r: 253,
                g: 104,
                b: 131,
            }, // op_color - pink
            Color::TrueColor {
                r: 133,
                g: 218,
                b: 204,
            }, // type_color - aqua
            Color::TrueColor {
                r: 0xa8,
                g: 0xa9,
                b: 0xeb,
            }, // const_color - lavender
            Color::TrueColor {
                r: 0x94,
                g: 0x8a,
                b: 0x8b,
            }, // low_prio - muted gray
            Color::TrueColor {
                r: 173,
                g: 218,
                b: 120,
            }, // function - lime green
            Color::TrueColor {
                r: 44,
                g: 37,
                b: 37,
            }, // bg_color - dark gray
        )
    }
    
    pub fn high_contrast_theme() -> Colors {
        // High contrast theme for better readability
        Colors::new(
            Color::BrightYellow, // keyword
            Color::BrightWhite,  // variable
            Color::BrightRed,    // op_color
            Color::BrightCyan,   // type_color
            Color::BrightGreen,  // const_color
            Color::BrightBlack,  // low_prio
            Color::BrightBlue,   // function
            Color::Black,        // bg_color
        )
    }
    
    pub fn light_theme() -> Colors {
        // Light theme for those who prefer light backgrounds
        Colors::new(
            Color::Blue,        // keyword
            Color::Black,       // variable
            Color::Red,         // op_color
            Color::Green,       // type_color
            Color::Magenta,     // const_color
            Color::BrightBlack, // low_prio
            Color::Cyan,        // function
            Color::White,       // bg_color
        )
    }
    
    pub fn monochrome_theme() -> Colors {
        // Simple monochrome theme for terminals with limited color support
        Colors::new(
            Color::White, // keyword
            Color::White, // variable
            Color::White, // op_color
            Color::White, // type_color
            Color::White, // const_color
            Color::White, // low_prio
            Color::White, // function
            Color::Black, // bg_color
        )
    }
    
    pub fn blue_accent_theme() -> Colors {
        // A dark theme with blue accents
        Colors::new(
            Color::TrueColor {
                r: 97,
                g: 175,
                b: 239,
            }, // keyword - bright blue
            Color::TrueColor {
                r: 224,
                g: 224,
                b: 224,
            }, // variable - light gray
            Color::TrueColor {
                r: 97,
                g: 175,
                b: 239,
            }, // op_color - bright blue
            Color::TrueColor {
                r: 152,
                g: 195,
                b: 121,
            }, // type_color - green
            Color::TrueColor {
                r: 209,
                g: 154,
                b: 102,
            }, // const_color - orange
            Color::TrueColor {
                r: 92,
                g: 99,
                b: 112,
            }, // low_prio - gray
            Color::TrueColor {
                r: 198,
                g: 120,
                b: 221,
            }, // function - purple
            Color::TrueColor {
                r: 40,
                g: 44,
                b: 52,
            }, // bg_color - dark blue-gray
        )
    }
    
    pub fn tokyo_night_theme() -> Colors {
        // Tokyo Night theme - dark blue background with vibrant accents
        Colors::new(
            Color::TrueColor {
                r: 0xbb,
                g: 0x9a,
                b: 0xf7,
            }, // keyword - purple (official)
            Color::TrueColor {
                r: 0xa9,
                g: 0xb1,
                b: 0xd6,
            }, // variable - lavender (official)
            Color::TrueColor {
                r: 0xff,
                g: 0x9e,
                b: 0x64,
            }, // op_color - orange (official)
            Color::TrueColor {
                r: 0x9e,
                g: 0xcc,
                b: 0xed,
            }, // type_color - light blue (official)
            Color::TrueColor {
                r: 0xff,
                g: 0x9e,
                b: 0x64,
            }, // const_color - orange (official)
            Color::TrueColor {
                r: 0x56,
                g: 0x5f,
                b: 0x89,
            }, // low_prio - gray-blue (official)
            Color::TrueColor {
                r: 0x7a,
                g: 0xa2,
                b: 0xf7,
            }, // function - blue (official)
            Color::TrueColor {
                r: 0x1a,
                g: 0x1b,
                b: 0x26,
            }, // bg_color - dark blue-black (official Tokyo Night color)
        )
    }
    
    pub fn tokyo_night_storm_theme() -> Colors {
        // Tokyo Night Storm theme - slightly lighter variation of Tokyo Night
        Colors::new(
            Color::TrueColor {
                r: 0xbb,
                g: 0x9a,
                b: 0xf7,
            }, // keyword - purple
            Color::TrueColor {
                r: 0xa9,
                g: 0xb1,
                b: 0xd6,
            }, // variable - lavender
            Color::TrueColor {
                r: 0xff,
                g: 0x9e,
                b: 0x64,
            }, // op_color - orange
            Color::TrueColor {
                r: 0x9e,
                g: 0xcc,
                b: 0xed,
            }, // type_color - light blue
            Color::TrueColor {
                r: 0xff,
                g: 0x9e,
                b: 0x64,
            }, // const_color - orange
            Color::TrueColor {
                r: 0x56,
                g: 0x5f,
                b: 0x89,
            }, // low_prio - gray-blue
            Color::TrueColor {
                r: 0x7a,
                g: 0xa2,
                b: 0xf7,
            }, // function - blue
            Color::TrueColor {
                r: 0x24,
                g: 0x28,
                b: 0x3b,
            }, // bg_color - medium blue-black (official Tokyo Night Storm color)
        )
    }
    
    pub fn catppuccin_mocha_theme() -> Colors {
        // Catppuccin Mocha theme - dark and cozy
        Colors::new(
            Color::TrueColor {
                r: 0xf3,
                g: 0x8b,
                b: 0xa8,
            }, // keyword - pink (official)
            Color::TrueColor {
                r: 0xcd,
                g: 0xd6,
                b: 0xf4,
            }, // variable - lavender (official)
            Color::TrueColor {
                r: 0xed,
                g: 0x8a,
                b: 0x96,
            }, // op_color - red (official)
            Color::TrueColor {
                r: 0xa6,
                g: 0xe3,
                b: 0xa1,
            }, // type_color - green (official)
            Color::TrueColor {
                r: 0xf9,
                g: 0xe2,
                b: 0xaf,
            }, // const_color - yellow (official)
            Color::TrueColor {
                r: 0x6c,
                g: 0x7c,
                b: 0x94,
            }, // low_prio - gray (official)
            Color::TrueColor {
                r: 0x89,
                g: 0xb4,
                b: 0xfa,
            }, // function - blue (official)
            Color::TrueColor {
                r: 0x1e,
                g: 0x1e,
                b: 0x2e,
            }, // bg_color - dark blue (official Catppuccin Mocha color)
        )
    }
    
    pub fn catppuccin_macchiato_theme() -> Colors {
        // Catppuccin Macchiato theme - medium dark and cozy
        Colors::new(
            Color::TrueColor {
                r: 0xf4,
                g: 0x8f,
                b: 0xb1,
            }, // keyword - pink
            Color::TrueColor {
                r: 0xca,
                g: 0xd3,
                b: 0xf5,
            }, // variable - lavender
            Color::TrueColor {
                r: 0xed,
                g: 0x8a,
                b: 0x96,
            }, // op_color - red
            Color::TrueColor {
                r: 0xa6,
                g: 0xda,
                b: 0x95,
            }, // type_color - green
            Color::TrueColor {
                r: 0xee,
                g: 0xd4,
                b: 0x9f,
            }, // const_color - yellow
            Color::TrueColor {
                r: 0x5b,
                g: 0x6c,
                b: 0x8c,
            }, // low_prio - gray
            Color::TrueColor {
                r: 0x8a,
                g: 0xaa,
                b: 0xed,
            }, // function - blue
            Color::TrueColor {
                r: 0x24,
                g: 0x27,
                b: 0x3a,
            }, // bg_color - medium dark blue (official Catppuccin Macchiato color)
        )
    }
    
    pub fn catppuccin_frappe_theme() -> Colors {
        // Catppuccin Frappe theme - balanced and cozy
        Colors::new(
            Color::TrueColor {
                r: 0xf4,
                g: 0x8f,
                b: 0xb1,
            }, // keyword - pink
            Color::TrueColor {
                r: 0xc6,
                g: 0xd0,
                b: 0xf5,
            }, // variable - lavender
            Color::TrueColor {
                r: 0xe7,
                g: 0x8c,
                b: 0x8c,
            }, // op_color - red
            Color::TrueColor {
                r: 0xa6,
                g: 0xd1,
                b: 0x89,
            }, // type_color - green
            Color::TrueColor {
                r: 0xe5,
                g: 0xc8,
                b: 0x90,
            }, // const_color - yellow
            Color::TrueColor {
                r: 0x62,
                g: 0x73,
                b: 0x8c,
            }, // low_prio - gray
            Color::TrueColor {
                r: 0x8c,
                g: 0xaa,
                b: 0xee,
            }, // function - blue
            Color::TrueColor {
                r: 0x30,
                g: 0x34,
                b: 0x46,
            }, // bg_color - medium blue (official Catppuccin Frappe color)
        )
    }
    
    pub fn catppuccin_latte_theme() -> Colors {
        // Catppuccin Latte theme - light and cozy
        Colors::new(
            Color::TrueColor {
                r: 0xd2,
                g: 0x0f,
                b: 0x39,
            }, // keyword - pink (official)
            Color::TrueColor {
                r: 0x4c,
                g: 0x4f,
                b: 0x69,
            }, // variable - dark lavender (official)
            Color::TrueColor {
                r: 0xd2,
                g: 0x0f,
                b: 0x39,
            }, // op_color - red (official)
            Color::TrueColor {
                r: 0x40,
                g: 0xa0,
                b: 0x2b,
            }, // type_color - green (official)
            Color::TrueColor {
                r: 0xdf,
                g: 0x8e,
                b: 0x1d,
            }, // const_color - yellow (official)
            Color::TrueColor {
                r: 0x6c,
                g: 0x6f,
                b: 0x85,
            }, // low_prio - gray (official)
            Color::TrueColor {
                r: 0x1e,
                g: 0x66,
                b: 0xf5,
            }, // function - blue (official)
            Color::TrueColor {
                r: 0xef,
                g: 0xf1,
                b: 0xf5,
            }, // bg_color - white (official Catppuccin Latte color)
        )
    }
    
    pub fn dracula_theme() -> Colors {
        // Dracula theme - dark theme with vibrant colors
        Colors::new(
            Color::TrueColor {
                r: 0xff,
                g: 0x79,
                b: 0xc6,
            }, // keyword - pink
            Color::TrueColor {
                r: 0xf8,
                g: 0xf8,
                b: 0xf2,
            }, // variable - off white
            Color::TrueColor {
                r: 0xff,
                g: 0x79,
                b: 0xc6,
            }, // op_color - pink
            Color::TrueColor {
                r: 0x8b,
                g: 0xe9,
                b: 0xfd,
            }, // type_color - cyan
            Color::TrueColor {
                r: 0xf1,
                g: 0xfa,
                b: 0x8c,
            }, // const_color - yellow
            Color::TrueColor {
                r: 0x62,
                g: 0x72,
                b: 0xa4,
            }, // low_prio - comment blue
            Color::TrueColor {
                r: 0x50,
                g: 0xfa,
                b: 0x7b,
            }, // function - green
            Color::TrueColor {
                r: 0x28,
                g: 0x2a,
                b: 0x36,
            }, // bg_color - dark background
        )
    }
    
    pub fn nord_theme() -> Colors {
        // Nord theme - arctic, north-bluish color palette
        Colors::new(
            Color::TrueColor {
                r: 0x81,
                g: 0xa1,
                b: 0xc1,
            }, // keyword - frost blue
            Color::TrueColor {
                r: 0xd8,
                g: 0xde,
                b: 0xe9,
            }, // variable - snow storm 1
            Color::TrueColor {
                r: 0x81,
                g: 0xa1,
                b: 0xc1,
            }, // op_color - frost blue
            Color::TrueColor {
                r: 0x8f,
                g: 0xbc,
                b: 0xbb,
            }, // type_color - frost cyan
            Color::TrueColor {
                r: 0xeb,
                g: 0xcb,
                b: 0x8b,
            }, // const_color - aurora yellow
            Color::TrueColor {
                r: 0x4c,
                g: 0x56,
                b: 0x6a,
            }, // low_prio - polar night 4
            Color::TrueColor {
                r: 0xa3,
                g: 0xbe,
                b: 0x8c,
            }, // function - aurora green
            Color::TrueColor {
                r: 0x2e,
                g: 0x34,
                b: 0x40,
            }, // bg_color - polar night 1
        )
    }
    
    pub fn solarized_dark_theme() -> Colors {
        // Solarized Dark theme - careful color selection based on fixed color wheel relationships
        Colors::new(
            Color::TrueColor {
                r: 0x26,
                g: 0x8b,
                b: 0xd2,
            }, // keyword - blue
            Color::TrueColor {
                r: 0x83,
                g: 0x94,
                b: 0x96,
            }, // variable - base0
            Color::TrueColor {
                r: 0x2a,
                g: 0xa1,
                b: 0x98,
            }, // op_color - cyan
            Color::TrueColor {
                r: 0x6c,
                g: 0x71,
                b: 0xc4,
            }, // type_color - violet
            Color::TrueColor {
                r: 0xb5,
                g: 0x89,
                b: 0x00,
            }, // const_color - yellow
            Color::TrueColor {
                r: 0x58,
                g: 0x6e,
                b: 0x75,
            }, // low_prio - base01
            Color::TrueColor {
                r: 0x85,
                g: 0x99,
                b: 0x00,
            }, // function - green
            Color::TrueColor {
                r: 0x00,
                g: 0x2b,
                b: 0x36,
            }, // bg_color - base03
        )
    }
    
    pub fn onedark_theme() -> Colors {
        // One Dark Pro - Atom's iconic One Dark theme
        Colors::new(
            Color::TrueColor {
                r: 0xc6,
                g: 0x78,
                b: 0xdd,
            }, // keyword - purple
            Color::TrueColor {
                r: 0xab,
                g: 0xb2,
                b: 0xbf,
            }, // variable - foreground
            Color::TrueColor {
                r: 0xc6,
                g: 0x78,
                b: 0xdd,
            }, // op_color - purple
            Color::TrueColor {
                r: 0x56,
                g: 0xb6,
                b: 0xc2,
            }, // type_color - cyan
            Color::TrueColor {
                r: 0xe5,
                g: 0xc0,
                b: 0x7b,
            }, // const_color - yellow
            Color::TrueColor {
                r: 0x54,
                g: 0x58,
                b: 0x62,
            }, // low_prio - gutter gray
            Color::TrueColor {
                r: 0x61,
                g: 0xaf,
                b: 0xef,
            }, // function - blue
            Color::TrueColor {
                r: 0x28,
                g: 0x2c,
                b: 0x34,
            }, // bg_color - background
        )
    }
    
    pub fn github_dark_theme() -> Colors {
        // GitHub Dark theme - official GitHub dark theme colors
        Colors::new(
            Color::TrueColor {
                r: 0xbc,
                g: 0x8c,
                b: 0xff,
            }, // keyword - purple
            Color::TrueColor {
                r: 0xc9,
                g: 0xd1,
                b: 0xd9,
            }, // variable - fg-default
            Color::TrueColor {
                r: 0x79,
                g: 0xc0,
                b: 0xff,
            }, // op_color - bright blue
            Color::TrueColor {
                r: 0x79,
                g: 0xc0,
                b: 0xff,
            }, // type_color - bright blue
            Color::TrueColor {
                r: 0xe3,
                g: 0xb3,
                b: 0x41,
            }, // const_color - yellow
            Color::TrueColor {
                r: 0x8b,
                g: 0x94,
                b: 0x9e,
            }, // low_prio - gray
            Color::TrueColor {
                r: 0x3f,
                g: 0xb9,
                b: 0x50,
            }, // function - green
            Color::TrueColor {
                r: 0x0d,
                g: 0x11,
                b: 0x17,
            }, // bg_color - dark background
        )
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
            description: "Default dark theme with pink accent colors" 
        },
        ThemeInfo { 
            name: "high-contrast", 
            description: "High contrast theme for better readability" 
        },
        ThemeInfo { 
            name: "light", 
            description: "Light theme for those who prefer light backgrounds" 
        },
        ThemeInfo { 
            name: "monochrome", 
            description: "Simple monochrome theme for limited color support" 
        },
        ThemeInfo { 
            name: "blue", 
            description: "A dark theme with blue accents" 
        },
        ThemeInfo { 
            name: "tokyo-night", 
            description: "Tokyo Night theme - dark blue background with vibrant accents" 
        },
        ThemeInfo { 
            name: "tokyo-night-storm", 
            description: "Tokyo Night Storm theme - slightly lighter variation of Tokyo Night" 
        },
        ThemeInfo { 
            name: "catppuccin-mocha", 
            description: "Catppuccin Mocha theme - dark and cozy" 
        },
        ThemeInfo { 
            name: "catppuccin-macchiato", 
            description: "Catppuccin Macchiato theme - medium dark and cozy" 
        },
        ThemeInfo { 
            name: "catppuccin-frappe", 
            description: "Catppuccin Frappe theme - balanced and cozy" 
        },
        ThemeInfo { 
            name: "catppuccin-latte", 
            description: "Catppuccin Latte theme - light and cozy" 
        },
        ThemeInfo { 
            name: "dracula", 
            description: "Dracula theme - dark theme with vibrant colors" 
        },
        ThemeInfo { 
            name: "nord", 
            description: "Nord theme - arctic, north-bluish color palette" 
        },
        ThemeInfo { 
            name: "solarized-dark", 
            description: "Solarized Dark - precision colors with careful color selection" 
        },
        ThemeInfo { 
            name: "onedark", 
            description: "One Dark Pro - Atom's iconic One Dark theme" 
        },
        ThemeInfo { 
            name: "github-dark", 
            description: "GitHub Dark - official GitHub dark theme colors" 
        },
    ];

    // Get a list of all available theme names
    pub fn get_theme_names() -> Vec<&'static str> {
        Self::THEMES.iter().map(|info| info.name).collect()
    }

    // Get theme descriptions for display
    pub fn get_theme_descriptions() -> Vec<(&'static str, &'static str)> {
        Self::THEMES.iter().map(|info| (info.name, info.description)).collect()
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