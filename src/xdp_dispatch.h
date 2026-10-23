#ifndef XDP_DISPATCH_H
#define XDP_DISPATCH_H

#define COMMAND_MAGIC 0x58445043

enum xdp_program_id {
  PROGRAM_FORWARD,
  PROGRAM_REWRITE,
  PROGRAM_COUNT,
};

union xdp_arguments {
  __u64 raw[2];
  struct {
    __u32 vni;
    __u32 flags;
    __u32 inner_len;
    __u32 flow_hash;
  } vxlan;
};

struct xdp_command {
  __u64 program;
  __u64 magic;
  union xdp_arguments args;
};

_Static_assert(sizeof(union xdp_arguments) == 16, "arguments must be 16 bytes");
_Static_assert(__builtin_offsetof(struct xdp_command, args) == 16,
               "command header must be 16 bytes");
_Static_assert(sizeof(struct xdp_command) == 32,
               "metadata ABI must be 32 bytes");

static __always_inline struct xdp_command* read_command(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  struct xdp_command* command = (void*)(long)ctx->data_meta;
  if ((void*)(command + 1) > data || command->magic != COMMAND_MAGIC ||
      command->program >= PROGRAM_COUNT)
    return 0;
  return command;
}

static __always_inline int write_command(struct xdp_md* ctx, __u32 program,
                                         union xdp_arguments args) {
  if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_command))) return -1;
  void* data = (void*)(long)ctx->data;
  struct xdp_command* command = (void*)(long)ctx->data_meta;
  if ((void*)(command + 1) > data) return -1;
  command->program = program;
  command->magic = COMMAND_MAGIC;
  command->args = args;
  return 0;
}

static __always_inline int dispatch_command(struct xdp_md* ctx,
                                            void* programs) {
  struct xdp_command* command = read_command(ctx);
  if (!command) return XDP_DROP;
  bpf_tail_call(ctx, programs, command->program);
  return XDP_DROP;
}

#endif
