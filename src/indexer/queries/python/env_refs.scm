;; os.environ["FOO"]
(subscript
  value: (attribute
    object: (identifier) @os_mod
    attribute: (identifier) @environ_attr)
  (string (string_content) @var_name)
  (#eq? @os_mod "os")
  (#eq? @environ_attr "environ"))

;; os.environ.get("FOO")
(call
  function: (attribute
    object: (attribute
      object: (identifier) @os_mod
      attribute: (identifier) @environ_attr)
    attribute: (identifier) @get_method)
  arguments: (argument_list
    (string (string_content) @var_name))
  (#eq? @os_mod "os")
  (#eq? @environ_attr "environ")
  (#eq? @get_method "get"))

;; os.getenv("FOO")
(call
  function: (attribute
    object: (identifier) @os_mod
    attribute: (identifier) @getenv_method)
  arguments: (argument_list
    (string (string_content) @var_name))
  (#eq? @os_mod "os")
  (#eq? @getenv_method "getenv"))
