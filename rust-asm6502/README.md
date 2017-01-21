Notes from https://github.com/kondrak/disasm6502/issues/1#issuecomment-270060829

Np!

What I would recommend later is that you consider doing a wrapper on top of C API and when a user is going to implement a plugin using Rust there is a more "rustified" API.

For example backend plugins for ProDBG needs to implement plugins for a C API like this.

https://github.com/emoon/ProDBG/blob/master/api/rust/prodbg/src/backend.rs#L92

But the Rust plugins can use the Backend trait https://github.com/emoon/ProDBG/blob/master/api/rust/prodbg/src/backend.rs#L81 to implement a plugin which gives you a nicer to use API.

And then I have a macro here https://github.com/emoon/ProDBG/blob/master/api/rust/prodbg/src/backend.rs#L150 that hides some of the setup.

A very simple plugin would look something like this (un-tested but it's an idea)

pub struct MyBackend {
  foo: i32;
}

impl prodbg::Backend for MyBackend {
  fn update(&mut self, action: i32, reader: &mut Reader, writer: &mut Writer) -> DebugState {
     ...
  }
}

define_backend_plugin!(PLUGIN, b"My Cool Backend\0", MyBackend);
