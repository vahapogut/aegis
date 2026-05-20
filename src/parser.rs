use tree_sitter::{Language, Parser, Tree};
use anyhow::Result;

pub struct TsParser {
    ts_parser: Parser,
    tsx_parser: Parser,
    py_parser: Parser,
    go_parser: Parser,
}

impl TsParser {
    pub fn new() -> Result<Self> {
        let mut ts_parser = Parser::new();
        let ts_lang: Language = tree_sitter_typescript::language_typescript();
        ts_parser.set_language(&ts_lang)
            .map_err(|e| anyhow::anyhow!("Failed to set TypeScript language: {:?}", e))?;

        let mut tsx_parser = Parser::new();
        let tsx_lang: Language = tree_sitter_typescript::language_tsx();
        tsx_parser.set_language(&tsx_lang)
            .map_err(|e| anyhow::anyhow!("Failed to set TSX language: {:?}", e))?;

        let mut py_parser = Parser::new();
        let py_lang: Language = tree_sitter_python::language();
        py_parser.set_language(&py_lang)
            .map_err(|e| anyhow::anyhow!("Failed to set Python language: {:?}", e))?;

        let mut go_parser = Parser::new();
        let go_lang: Language = tree_sitter_go::language();
        go_parser.set_language(&go_lang)
            .map_err(|e| anyhow::anyhow!("Failed to set Go language: {:?}", e))?;

        Ok(Self {
            ts_parser,
            tsx_parser,
            py_parser,
            go_parser,
        })
    }

    pub fn parse(&mut self, source_code: &str, lang: &str) -> Option<Tree> {
        match lang {
            "python" => self.py_parser.parse(source_code, None),
            "tsx" => self.tsx_parser.parse(source_code, None),
            "go" => self.go_parser.parse(source_code, None),
            _ => self.ts_parser.parse(source_code, None),
        }
    }

    pub fn get_language(&self, lang: &str) -> Language {
        match lang {
            "python" => tree_sitter_python::language(),
            "tsx" => tree_sitter_typescript::language_tsx(),
            "go" => tree_sitter_go::language(),
            _ => tree_sitter_typescript::language_typescript(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_new() {
        let parser = TsParser::new();
        assert!(parser.is_ok());
    }

    #[test]
    fn test_parse_typescript() {
        let mut parser = TsParser::new().unwrap();
        let tree = parser.parse("const x: number = 1;", "typescript");
        assert!(tree.is_some());
        let tree = tree.unwrap();
        assert!(tree.root_node().to_sexp().contains("program"));
    }

    #[test]
    fn test_parse_typescript_tsx() {
        let mut parser = TsParser::new().unwrap();
        // Parsing using TSX parser
        let tree = parser.parse("const el = <div />;", "tsx");
        assert!(tree.is_some());
        let tree = tree.unwrap();
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn test_parse_python() {
        let mut parser = TsParser::new().unwrap();
        let tree = parser.parse("x = 1", "python");
        assert!(tree.is_some());
        let tree = tree.unwrap();
        assert!(tree.root_node().to_sexp().contains("module"));
    }

    #[test]
    fn test_parse_go() {
        let mut parser = TsParser::new().unwrap();
        let tree = parser.parse("package main\nfunc main() {}", "go");
        assert!(tree.is_some());
        let tree = tree.unwrap();
        assert!(tree.root_node().to_sexp().contains("source_file"));
    }

    #[test]
    fn test_parse_invalid_syntax() {
        let mut parser = TsParser::new().unwrap();
        let tree = parser.parse("!!!! @@@ invalid @@@", "typescript");
        if let Some(tree) = tree {
            // Tree-sitter handles errors gracefully — should still parse but with ERROR nodes
            assert!(tree.root_node().has_error());
        }
    }

    #[test]
    fn test_get_language_typescript() {
        let parser = TsParser::new().unwrap();
        let lang = parser.get_language("typescript");
        assert!(lang.version() > 0);
    }

    #[test]
    fn test_get_language_tsx() {
        let parser = TsParser::new().unwrap();
        let lang = parser.get_language("tsx");
        assert!(lang.version() > 0);
    }

    #[test]
    fn test_get_language_python() {
        let parser = TsParser::new().unwrap();
        let lang = parser.get_language("python");
        assert!(lang.version() > 0);
    }

    #[test]
    fn test_get_language_go() {
        let parser = TsParser::new().unwrap();
        let lang = parser.get_language("go");
        assert!(lang.version() > 0);
    }
}
