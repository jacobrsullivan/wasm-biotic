(component
  (core module $service
    (func (export "invoke") (param $candidate i32) (param $minimum i32) (result i32)
      local.get $candidate
      local.get $minimum
      i32.le_s
      if (result i32)
        i32.const -1
      else
        local.get $candidate
      end))
  (core instance $service-instance (instantiate $service))
  (func $invoke
    (param "candidate" s32)
    (param "minimum" s32)
    (result s32)
    (canon lift (core func $service-instance "invoke")))
  (export "invoke" (func $invoke)))
