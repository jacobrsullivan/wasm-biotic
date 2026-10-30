(component
  (import "downstream"
    (func $downstream
      (param "candidate" s32)
      (param "minimum" s32)
      (result s32)))
  (core module $supervisor
    (func (export "invoke") (param i32 i32) (result i32)
      (loop $spin
        br $spin)
      unreachable))
  (core instance $supervisor-instance (instantiate $supervisor))
  (func $invoke
    (param "candidate" s32)
    (param "minimum" s32)
    (result s32)
    (canon lift (core func $supervisor-instance "invoke")))
  (export "invoke" (func $invoke)))
