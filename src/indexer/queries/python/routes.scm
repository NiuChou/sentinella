;; @app.get("/path") / @router.post("/path")
(decorator
  (call
    function: (attribute
      object: (identifier) @router_var
      attribute: (identifier) @method)
    arguments: (argument_list
      (string (string_content) @route_path)))
  (#match? @method "^(get|post|put|patch|delete)$"))
