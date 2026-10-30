(component
  (core module $challenger
    (func (export "transform") (param i32) (result i32)
      local.get 0
      i32.const 1
      i32.add))
  (core instance $challenger-instance (instantiate $challenger))
  (func (export "transform") (param "input" s32) (result s32)
    (canon lift (core func $challenger-instance "transform"))))
