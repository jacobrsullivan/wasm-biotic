(component
  (import "downstream"
    (func $downstream
      (param "candidate" s32)
      (param "minimum" s32)
      (result s32)))
  (core func $downstream-core (canon lower (func $downstream)))
  (core module $supervisor
    (import "" "downstream"
      (func $downstream (param i32 i32) (result i32)))
    (func (export "invoke") (param $candidate i32) (param $minimum i32) (result i32)
      (local $worker-result i32)
      local.get $candidate
      local.get $minimum
      call $downstream
      local.set $worker-result
      local.get $worker-result
      i32.const 0
      i32.lt_s
      if (result i32)
        i32.const -1
      else
        local.get $worker-result
        i32.const 200
        i32.add
      end))
  (core instance $supervisor-instance
    (instantiate $supervisor
      (with "" (instance
        (export "downstream" (func $downstream-core))))))
  (func $invoke
    (param "candidate" s32)
    (param "minimum" s32)
    (result s32)
    (canon lift (core func $supervisor-instance "invoke")))
  (export "invoke" (func $invoke)))
