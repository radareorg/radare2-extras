#include <mach/mach_types.h>
#include <security/mac_policy.h>
#include <sys/systm.h>
#include <sys/vnode.h>

kern_return_t r2k_start (kmod_info_t * ki, void * d);
kern_return_t r2k_stop (kmod_info_t * ki, void * d);

static int r2_on_process_exec (kauth_cred_t cred, struct vnode * vp,
    struct vnode * script_vp, struct label * vnode_label,
    struct label * script_label, struct label * exec_label,
    struct componentname * cnp, u_int * cs_flags, void * mac_policy_attr,
    size_t mac_policy_attr_len);

static struct mac_policy_ops r2_policy_ops =
{
  .mpo_vnode_check_exec = r2_on_process_exec
};

static struct mac_policy_conf r2_policy_conf =
{
  .mpc_name = "r2k",
  .mpc_fullname = "radare2 kernel module",
  .mpc_labelnames = NULL,
  .mpc_labelname_count = 0,
  .mpc_ops = &r2_policy_ops,
  .mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK,
  .mpc_field_off = NULL,
  .mpc_runtime_flags = 0,
  .mpc_list = NULL,
  .mpc_data = NULL
};

static mac_policy_handle_t r2_policy_handle;

kern_return_t
r2k_start (kmod_info_t * ki,
                        void * d)
{
  printf ("r2k start()\n");
  mac_policy_register (&r2_policy_conf, &r2_policy_handle, d);
  return KERN_SUCCESS;
}

kern_return_t
r2k_stop (kmod_info_t * ki,
                       void * d)
{
  printf ("r2k stop()\n");
  mac_policy_unregister (r2_policy_handle);
  return KERN_SUCCESS;
}

static int
r2_on_process_exec (kauth_cred_t cred,
                       struct vnode * vp,
                       struct vnode * script_vp,
                       struct label * vnode_label,
                       struct label * script_label,
                       struct label * exec_label,
                       struct componentname * cnp,
                       u_int * cs_flags,
                       void * mac_policy_attr,
                       size_t mac_policy_attr_len)
{
  char program_path[MAXPATHLEN];
  char script_path[MAXPATHLEN];
  int length;

  length = sizeof (program_path);
  vn_getpath (vp, program_path, &length);

  if (script_vp != NULL)
  {
    length = sizeof (script_path);
    vn_getpath (script_vp, script_path, &length);

    printf ("r2k exec: \"%s\" script: \"%s\"\n",
        program_path, script_path);
  }
  else
  {
    printf ("r2k exec: \"%s\"\n", program_path);
  }

  return 0;
}
