;; process.env.FOO
(member_expression
  object: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @env_prop)
  property: (property_identifier) @var_name
  (#eq? @obj "process")
  (#eq? @env_prop "env"))

;; process.env["FOO"]
(subscript_expression
  object: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @env_prop)
  index: (string (string_fragment) @var_name)
  (#eq? @obj "process")
  (#eq? @env_prop "env"))
