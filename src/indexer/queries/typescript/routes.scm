;; NestJS @Controller("/prefix") on class
(decorator
  (call_expression
    function: (identifier) @decorator_name
    arguments: (arguments
      (string (string_fragment) @controller_path)))
  (#eq? @decorator_name "Controller"))

;; NestJS decorators: @Get("/path"), @Post("/path")
(decorator
  (call_expression
    function: (identifier) @decorator_name
    arguments: (arguments
      (string (string_fragment) @route_path)))
  (#match? @decorator_name "^(Get|Post|Put|Patch|Delete)$"))

;; Express router: router.get("/path", handler)
(call_expression
  function: (member_expression
    object: (identifier) @router_var
    property: (property_identifier) @method_name)
  arguments: (arguments
    .
    (string (string_fragment) @route_path))
  (#match? @method_name "^(get|post|put|patch|delete|use)$"))
