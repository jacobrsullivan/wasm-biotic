(component
  (core module $incumbent
    (func (export "transform") (param i32) (result i32)
      local.get 0))
  (core instance $incumbent-instance (instantiate $incumbent))
  (func (export "transform") (param "input" s32) (result s32)
    (canon lift (core func $incumbent-instance "transform"))))
