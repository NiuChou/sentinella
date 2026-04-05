;; Named imports: import { foo } from "./module"
(import_statement
  (import_clause
    (named_imports
      (import_specifier
        name: (identifier) @imported_name)))
  source: (string (string_fragment) @source_path))

;; Default import: import Foo from "./module"
(import_statement
  (import_clause
    (identifier) @default_import)
  source: (string (string_fragment) @source_path))

;; Namespace import: import * as foo from "./module"
(import_statement
  (import_clause
    (namespace_import (identifier) @namespace_import))
  source: (string (string_fragment) @source_path))

;; Dynamic import: import("./module")
(call_expression
  function: (import)
  arguments: (arguments
    [(string (string_fragment) @source_path)
     (template_string) @template_source]))
