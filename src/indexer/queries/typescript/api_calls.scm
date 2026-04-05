;; fetch("/api/...")
(call_expression
  function: (identifier) @fn_name
  arguments: (arguments
    .
    [(string (string_fragment) @url)
     (template_string) @template_url])
  (#eq? @fn_name "fetch"))

;; axios.get("/api/..."), http.post("/api/...")
(call_expression
  function: (member_expression
    object: (identifier) @client
    property: (property_identifier) @method)
  arguments: (arguments
    .
    [(string (string_fragment) @url)
     (template_string) @template_url])
  (#match? @client "^(axios|http|api|client)$")
  (#match? @method "^(get|post|put|patch|delete|request)$"))
