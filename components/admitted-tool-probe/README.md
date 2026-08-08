# Admitted tool probe

This crate compiles to the `admitted-tool-component` world. It is the concrete
tool in the bounded v1 release graph: it reads an immutable input blob and
writes a deterministic JSON result. It has no process, shell, filesystem or
network interface. Its only import is the graph-declared `blob-store`
mechanism.
