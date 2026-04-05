;; r.GET("/path", handler) — Gin/Echo style
(call_expression
  function: (selector_expression
    operand: (identifier) @router_var
    field: (field_identifier) @method)
  arguments: (argument_list
    .
    (interpreted_string_literal) @route_path)
  (#match? @method "^(GET|POST|PUT|PATCH|DELETE|Use|Group)$"))
