#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <generated/utsrelease.h>
#include <generated/compile.h>
#include <linux/version.h> /* LINUX_VERSION_CODE, KERNEL_VERSION macros */
#include <linux/workqueue.h>

#include "allowlist.h"
#include "core_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "throne_tracker.h"

static struct workqueue_struct *ksu_workqueue;

bool ksu_queue_work(struct work_struct *work)
{
	return queue_work(ksu_workqueue, work);
}

#ifdef KSU_USE_STRUCT_FILENAME
extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
					void *argv, void *envp, int *flags);

extern int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
				    void *argv, void *envp, int *flags);

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					    flags);
}
#endif // KSU_USE_STRUCT_FILENAME

// track backports and other quirks here
// ref: kernel_compat.c, Makefile
// yes looks nasty
static const char *ksuver(void)
{
	// 256 enough currently, rember to raise!
	static char features[256] = __stringify(KSU_VERSION);

#ifdef KSU_USE_STRUCT_FILENAME
	strcat(features, " +uses_struct_filename");
#endif
#ifndef CONFIG_KSU_LSM_SECURITY_HOOKS
	strcat(features, " -lsm_hooks");
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) && defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	strcat(features, " +allowlist_workaround");
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)) && defined(KSU_HAS_MODERN_EXT4)
	strcat(features, " +ext4_unregister_sysfs");
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)) && defined(KSU_HAS_GET_CRED_RCU)
	strcat(features, " +get_cred_rcu");
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)) && defined(KSU_HAS_PATH_UMOUNT)
	strcat(features, " +path_umount");
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)) && defined(KSU_STRNCPY_FROM_USER_NOFAULT)
	strcat(features, " +strncpy_from_user_nofault");
#endif
#if !(LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)) && defined(KSU_STRNCPY_FROM_UNSAFE_USER)
	strcat(features, " +strncpy_from_unsafe_user");
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) && defined(KSU_NEW_KERNEL_READ)
	strcat(features, " +new_kernel_read");
#endif
#if !(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) && defined(KSU_NEW_KERNEL_WRITE)
	strcat(features, " +new_kernel_write");
#endif
	return features;
}

int __init kernelsu_init(void)
{
	pr_info("Initialized on: %s (%s) with ksuver: %s\n", UTS_RELEASE, UTS_MACHINE, ksuver());

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running KernelSU in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

	ksu_core_init();

	ksu_workqueue = alloc_ordered_workqueue("kernelsu_work_queue", 0);

	ksu_allowlist_init();

	ksu_throne_tracker_init();

	return 0;
}

void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_throne_tracker_exit();

	destroy_workqueue(ksu_workqueue);

}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
