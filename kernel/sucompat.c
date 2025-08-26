#include <linux/dcache.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
#include <linux/susfs_def.h>
#endif

#include "objsec.h"
#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

extern void escape_to_root();

static bool ksu_sucompat_non_kp __read_mostly = true;

static const char sh_path[] = "/system/bin/sh";
static const char ksud_path[] = KSUD_PATH;
static const char su[] = SU_PATH;

static inline void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static inline char __user *sh_user_path(void)
{

	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static inline char __user *ksud_user_path(void)
{

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

// every little bit helps here
__attribute__((hot, no_stack_protector))
static __always_inline bool is_su_allowed(const void *ptr_to_check)
{
	barrier();
	if (!ksu_sucompat_non_kp)
		return false;

	if (likely(!ksu_is_allow_uid(current_uid().val)))
		return false;

	if (unlikely(!ptr_to_check))
		return false;

	return true;
}

static int ksu_sucompat_user_common(const char __user **filename_user,
				const char *syscall_name,
				const bool escalate)
{

	char path[sizeof(su)]; // sizeof includes nullterm already!
	if (ksu_copy_from_user_retry(path, *filename_user, sizeof(path)))
		return 0;

	path[sizeof(path) - 1] = '\0';

#ifndef CONFIG_KSU_SUSFS_SUS_SU
	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_SU
	char path[sizeof(su) + 1] = {0};
#else
	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
#endif
	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		pr_info("faccessat su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && defined(CONFIG_KSU_SUSFS_SUS_SU)
struct filename* susfs_ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags) {
	struct filename *name = getname_flags(*filename_user, getname_statx_lookup_flags(*flags), NULL);

	if (unlikely(IS_ERR(name) || name->name == NULL)) {
		return name;
	}

	if (likely(memcmp(name->name, su, sizeof(su)))) {
		return name;
	}

	const char sh[] = SH_PATH;
	pr_info("vfs_fstatat su->sh!\n");
	memcpy((void *)name->name, sh, sizeof(sh));
	return name;
}
#endif

// sys_faccessat
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	if (!is_su_allowed((const void *)filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "faccessat", false);
}

// sys_newfstatat, sys_fstat64
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{

#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_non_kp){
		return 0;
	}
#endif

#ifndef CONFIG_KSU_SUSFS_SUS_SU
	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}
#endif

	if (unlikely(!filename_user)) {
		return 0;
	}

#ifdef CONFIG_KSU_SUSFS_SUS_SU
	char path[sizeof(su) + 1] = {0};
#else	
	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
#endif
// Remove this later!! we use syscall hook, so this will never happen!!!!!
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0) && 0
	// it becomes a `struct filename *` after 5.18
	// https://elixir.bootlin.com/linux/v5.18/source/fs/stat.c#L216
	const char sh[] = SH_PATH;
	struct filename *filename = *((struct filename **)filename_user);
	if (IS_ERR(filename)) {
		return 0;
	}
	if (likely(memcmp(filename->name, su, sizeof(su))))
		return 0;

	if (escalate) {
		pr_info("%s su found\n", function_name);
		memcpy(filename_ptr, KSUD_PATH, sizeof(KSUD_PATH));
		escape_to_root();
	} else {
		pr_info("%s su->sh\n", function_name);
		memcpy(filename_ptr, SH_PATH, sizeof(SH_PATH));
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
// for do_execveat_common / do_execve_common on >= 3.14
// take note: struct filename **filename
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;

#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_non_kp) {
		return 0;
	}
#endif

	if (unlikely(!filename_ptr))
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename)) {
		return 0;
	}

	if (likely(memcmp(filename->name, su, sizeof(su))))
		return 0;

#ifndef CONFIG_KSU_SUSFS_SUS_SU
	if (!ksu_is_allow_uid(current_uid().val))
		return 0;
#endif

	pr_info("do_execveat_common su found\n");
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_to_root();

	return 0;
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
			       void *__never_use_argv, void *__never_use_envp,
			       int *__never_use_flags)
{
	//const char su[] = SU_PATH;
#ifdef CONFIG_KSU_SUSFS_SUS_SU
	char path[sizeof(su) + 1] = {0};
#else
 	char path[sizeof(su) + 1];
#endif

#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_non_kp) {
		return 0;

	return ksu_sucompat_kernel_common((void *)*filename_ptr, "do_execve_common", true);
}
#endif

// getname_flags on fs/namei.c, this hooks ALL fs-related syscalls.
// put the hook right after usercopy
// NOT RECOMMENDED for daily use. mostly for debugging purposes.
int ksu_getname_flags_kernel(char **kname, int flags)
{
	if (!is_su_allowed((const void *)kname))
		return 0;

#ifndef CONFIG_KSU_SUSFS_SUS_SU
 	memset(path, 0, sizeof(path));
#endif
	ksu_strncpy_from_user_retry(path, *filename_user, sizeof(path));

	if (likely(memcmp(path, su, sizeof(su))))
		return 0;

	if (!ksu_is_allow_uid(current_uid().val))
		return 0;

	pr_info("sys_execve su found\n");
	*filename_user = ksud_user_path();

	escape_to_root();

	return 0;
}

int ksu_handle_devpts(struct inode *inode)
{
	return 0;
}

int __ksu_handle_devpts(struct inode *inode)
{
	barrier();
	if (!ksu_sucompat_non_kp)
		return 0;

	if (!current->mm) {
		return 0;
	}

	uid_t uid = current_uid().val;
	if (uid % 100000 < 10000) {
		// not untrusted_app, ignore it
		return 0;
	}

	if (likely(!ksu_is_allow_uid(uid)))
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	struct inode_security_struct *sec = selinux_inode(inode);
#else
	struct inode_security_struct *sec = (struct inode_security_struct *)inode->i_security;
#endif
	if (ksu_devpts_sid && sec)
		sec->sid = ksu_devpts_sid;

	return 0;
}

// sucompat: permited process can execute 'su' to gain root access.
void ksu_sucompat_init()
{
	ksu_sucompat_non_kp = true;
	pr_info("ksu_sucompat_init: hooks enabled: execve/execveat_su, faccessat, stat, devpts\n");
}

void ksu_sucompat_exit()
{
	ksu_sucompat_non_kp = false;
	pr_info("ksu_sucompat_exit: hooks disabled: execve/execveat_su, faccessat, stat, devpts\n");
}

#ifdef CONFIG_KSU_SUSFS_SUS_SU
extern bool ksu_su_compat_enabled;
bool ksu_devpts_hook = false;
bool susfs_is_sus_su_hooks_enabled __read_mostly = false;
int susfs_sus_su_working_mode = 0;

static bool ksu_is_su_kps_enabled(void) {
	for (int i = 0; i < ARRAY_SIZE(su_kps); i++) {
		if (su_kps[i]) {
			return true;
		}
	}
	return false;
}

void ksu_susfs_disable_sus_su(void) {
	susfs_is_sus_su_hooks_enabled = false;
	ksu_devpts_hook = false;
	susfs_sus_su_working_mode = SUS_SU_DISABLED;
	// Re-enable the su_kps for user, users need to toggle off the kprobe hooks again in ksu manager if they want it disabled.
	if (!ksu_is_su_kps_enabled()) {
		ksu_sucompat_init();
		ksu_su_compat_enabled = true;
	}
}

void ksu_susfs_enable_sus_su(void) {
	if (ksu_is_su_kps_enabled()) {
		ksu_sucompat_exit();
		ksu_su_compat_enabled = false;
	}
	susfs_is_sus_su_hooks_enabled = true;
	ksu_devpts_hook = true;
	susfs_sus_su_working_mode = SUS_SU_WITH_HOOKS;
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_SU

