(component
  ;; Negative control: this intentionally references a missing core function.
  (func (export "transform") (param "input" s32) (result s32)
    (canon lift (core func $missing "transform"))))
