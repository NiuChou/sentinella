;; router.use(authMiddleware) — identifier argument
(call_expression
  function: (member_expression
    object: (identifier) @router_var
    property: (property_identifier) @use_method)
  arguments: (arguments
    (identifier) @middleware_name)
  (#eq? @use_method "use"))

;; router.use(cors()) — call expression argument
(call_expression
  function: (member_expression
    object: (identifier) @router_var
    property: (property_identifier) @use_method)
  arguments: (arguments
    (call_expression
      function: (identifier) @middleware_name))
  (#eq? @use_method "use"))

;; router.use(passport.authenticate("jwt")) — member expression call
(call_expression
  function: (member_expression
    object: (identifier) @router_var
    property: (property_identifier) @use_method)
  arguments: (arguments
    (call_expression
      function: (member_expression
        object: (identifier) @middleware_obj
        property: (property_identifier) @middleware_name)))
  (#eq? @use_method "use"))
