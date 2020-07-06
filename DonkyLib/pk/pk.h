#pragma once

#include "pk_defs.h"
#include "pk_debug.h"
#include "pk_arch.h"

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

//------------------------------------------------------------------------------
// PK API Defines
//------------------------------------------------------------------------------

#define PK_DOMAIN_ROOT               0
#define PK_DOMAIN_CURRENT           -1
#define PK_DOMAIN_ANY               -2

#define PK_DEFAULT_KEY              -1

// Virtual protection key
typedef int vkey_t;
#define VKEY_MAX INT_MAX
#define VKEY_INVALID                -1

#define PK_SLOT_ANY                 -1
#define PK_SLOT_NONE                -2

#define PK_ECALL_ANY                -1

enum {
  PK_KEY_OWNER   = 1,
  PK_KEY_COPY    = 2,
  PK_KEY_SHARED  = 4,
  PK_KEY_INHERIT = 8,
};

//------------------------------------------------------------------------------
// PK API Functions
//------------------------------------------------------------------------------

/**
 * @brief Initialize PK
 * 
 * This function initializes PK. It needs to be called
 * at the beginning of your program. If not initialized, all other 
 * @c pk_ API functions will fail with @c EACCES.
 * 
 * This function will set up the current code as root domain with did
 * equal to @c PK_DOMAIN_ROOT. The current stack is automatically
 * protected by the domain's default key. To also protect code/data, use
 * @c pk_module_protect.
 * 
 * If compiled with CONSTRUCTOR=1, pk_init will be called automatically
 * at program start.
 * 
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            Todo: specify
 */
int pk_init(void);


/**
 * @brief Deinitialize PK
 * 
 * This function deinitializes PK. For this to work, all domains except
 * the root domain have to be freed first via @c pk_domain_free.
 * 
 * If compiled with CONSTRUCTOR=1, pk_deinit will be called automatically
 * at program exit. This might require @c LD_BIND_NOW=1.
 * 
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            Todo: specify
 */
int pk_deinit(void);


/**
 * @brief Create a new domain
 * 
 * This function creates a new protection domain with its own private
 * protection key. The new domain will be a child of the current domain.
 * The parent domain can use @a pk_pkey_mprotect2, 
 * @a pk_domain_register_ecall2 and @a pk_domain_allow_caller2 to
 * prepare their child domains.
 * 
 * @param flags
 *         0
 *            Protection key of new domain is guaranteed to be unique
 *         @c PK_KEY_SHARED
 *            Protection key of new domain can be shared. This allows
 *            to allocate a higher number of protection keys than the
 *            architecture natively supports. However, it only gives
 *            probabilistic isolation guarantees.
 *         @c PK_KEY_INHERIT
 *            Protection key of new domain is inherited to the calling
 *            domain as if the new domain executed @c pk_domain_assign_pkey(
 *                did, vkey, 0 [|PK_KEY_COPY] [|PK_KEY_OWNER], 0)
 *         @c PK_KEY_COPY
 *            Only valid with @c PK_KEY_INHERIT
 *         @c PK_KEY_OWNER
 *            Only valid with @c PK_KEY_INHERIT
 *         @c PK_KEY_O
 * @return
 *        The new domain id @c did, which is always positive,
 *        or -1 on error, and errno is set to:
 *        @c EINVAL
 *            if @p flags are invalid.
 *        @c ENOMEM
 *            if there is no more space for new domains
 */
int pk_domain_create(unsigned int flags);


/**
 * @brief Relinquish control over child domain
 * 
 * This function removes a parent-child relationship such that the
 * calling domain cannot act on behalf of its child anymore.
 *
 * @param did 
 *        The child domain to release.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is not a child domain
 */
int pk_domain_release_child(int did);


/**
 * @brief Frees a domain
 * 
 * This function cleans up a protection domain. 
 * It requires any allocated protection keys to be free'd.
 * 
 * @param did
 *        The domain to free. Can be @c PK_DOMAIN_CURRENT.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is not a child domain
 *        @c EPERM
 *            if @p did has allocated protection keys that are not yet
 *            free'd
 */
int pk_domain_free(int did);


/**
 * @brief Allocate a new protection key. 
 * 
 * This function allocates a new protection key via @c pkey_alloc.
 * In addition, it assigns the allocated protection key to the
 * current protection domain. The protection key might be transferred to
 * other domains via @a pk_domain_assign_pkey.
 * 
 * @param flags
 *         0
 *            Allocated protection key is guaranteed to be unique
 *         @c PK_KEY_SHARED
 *            Allocated protection key can be shared across different calls to
 *            @c pk_pkey_alloc. This allows to allocate a higher number
 *            of protection keys than the architecture natively
 *            supports. However, it only gives probabilistic isolation
 *            guarantees. Hence, such keys are called virtual protection key.
 * @param access_rights 
 *         may contain zero or more disable operations:
 *         @c PKEY_DISABLE_ACCESS
 *            Disables both read and write access. Code fetces might
 *            still be allowed, depending on the architecture.
 *         @c PKEY_DISABLE_WRITE
 *            Disables write access.
 *         TODO: Who enforces access_rights on which level? Is this the default policy? Or is this so legacy that it is obsolete?
 * @return
 *        The allocated protection key, which is always positive,
 *        or PK_VKEY_INVALID (which is -1) on error, and errno is set to:
 *        @c EINVAL
 *            if @p flags or @p access_rights is invalid.
 *        @c ENOSPC
 *            if no more free protection keys are available, or the
 *            architecture does not support protection keys.
 */
vkey_t pk_pkey_alloc(unsigned int flags, unsigned int access_rights);


/**
 * @brief Free a protection key
 * 
 * This function frees a protection key. It does so by first
 * unloading it from the current thread via 
 * @c pk_domain_load_key(PK_DOMAIN_CURRENT, SLOT_NONE, 0), and then
 * handing it back to the kernel via @c pkey_free.
 * 
 * In order to free a vkey, it must not be in use, e.g. by @c pk_pkey_mprotect.
 * Either unuse it by another call to @c pk_pkey_mprotect clearing the
 * @p vkey, or unmap all relevant pages first via @c pk_unmap. Also, 
 * the key must not be loaded in foreign threads via @c pk_domain_load_key, 
 * or it must be unloaded first via 
 * @c pk_domain_load_key(PK_DOMAIN_CURRENT, SLOT_NONE, 0).
 * 
 * The protection key has to be allocated via @a pk_pkey_alloc. A domain
 * cannot free its default key. Moreover, the current domain needs
 * to have ownership. A domain has ownership either by executing
 * @a pk_pkey_alloc itself and not delegating ownership, or it was
 * granted ownership via @a pk_domain_assign_pkey and the
 * @c PK_KEY_OWNER flag.
 * 
 * The @p vkey is free'd for all domains that may hold a copy via
 * @a pk_domain_assign_pkey with the @c PK_KEY_COPY flag.
 *
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if current domain does not own @p vkey.
 *        @c EPERM
 *            if key is still in use
 */
int pk_pkey_free(vkey_t vkey);


/**
 * @brief Assign a protection key to a domain
 * 
 * This function assigns a protection key to a domain. The key has to
 * be allocated via @a pk_pkey_alloc, and the current domain needs to
 * have proper access to it. A domain can assign a protection key if
 * it has executed @a pk_pkey_alloc itself and did not transfer ownership,
 * or it was granted access to the key via @a pk_domain_assign_pkey without
 * the @c PK_KEY_COPY flag.
 * 
 * A domain can also assign a protection key to itself, in which case
 * the original key will be lost. E.g. a domain can drop @p access_rights
 * onto a @p vkey while keeping ownership via @c PK_KEY_OWNER, or losing
 * ownership via @c PK_KEY_COPY. 
 * 
 * @param did 
 *        The domain to assign the protection key to. Can be 
 *        @c PK_DOMAIN_CURRENT to reduce its privileges.
 * @param vkey
 *        The protection key
 * @param flags
 *        A bitwise combination by any of those
 *        @c PK_KEY_OWNER
 *            The new domain gets ownership, allowing it to use @p vkey
 *            for memory mapping (@p pk_mmap, @p pk_munmap, @p pk_mprotect, 
 *            @p pk_pkey_mprotect) and free it via @p pk_pkey_free.
 *        @c PK_KEY_COPY
 *            The new domain gets a copy of @p vkey which it can use for
 *            accessing memory assigned to @p vkey, or making other
 *            copies with the @c PK_KEY_COPY flag. Depending on
 *            @c PK_KEY_OWNER, this copy has ownership access. Without
 *            this flag, the current domain loses access to @p vkey.
 * @param access_rights
 *        The access rights for @p vkey. They must be equal or more
 *        restrictive than the current domain's access rights for this
 *        @p vkey.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EINVAL
 *            if @p did, @p flags or @p access_rights is invalid.
 *        @c EACCES
 *            if the current domain does not own @p vkey, or
 *            if @p access_rights is more permissive than current
 *            domain's access rights
 *        @c ENOMEM
 *            if there is no more space for assigning @p pkeys
 */
int pk_domain_assign_pkey(int did, vkey_t vkey, int flags, int access_rights);


/**
 * @brief Get a domain's default protection key
 * 
 * This function retrieves a domain's default protection key, which is
 * allocated at pk_domain_create.
 * 
 * @param did
 *        The domain, which must be the current or a child domain
 * @return
 *        vkey on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is not current or child domain
 */
int pk_domain_default_key(int did);


/**
 * @brief Protect a memory range with a protection key
 * 
 * This function protects a memory range via @c pkey_mprotect. In addition,
 * the current domain needs to have access to @p vkey, and the requested
 * protection needs to be allowed by this @p vkey.
 *
 * @param did
 *        The domain to which the memory range belongs. Must be the
 *        current or a child domain. If omitted or set to
 *        @c PK_DOMAIN_CURRENT, the current domain.
 * @param addr
 *        The page-aligned address pointing to the start of the memory
 *        range to protect.
 * @param len
 *        The length in bytes of the memory range to protect.
 * @param prot
 *        Any combination of @c PROT_NONE, @c PROT_READ, @c PROT_WRITE,
 *        @c PROT_EXEC, etc. allowed by @c pkey_mprotect.
 * @param vkey
 *        The protection key. Can be @c PK_DEFAULT_KEY to specify the
 *        default key of the domain @p did.
 * @return
 *        0 on success, or -1 on error, and errno is set according to @c pkey_mprotect
 *        @c EINVAL
 *            if @p vkey is invalid.
 *        @c EACCES
 *            if @p did is not current or child domain, or
 *            if current domain does not own @p vkey, or
 *            if the address range is owned by a different @p vkey
 *        @c ENOMEM
 *            if there is no more space for keeping track of mprotect calls
 *        Any other error code specified for @c pkey_mprotect.
 */
int pk_pkey_mprotect(void *addr, size_t len, int prot, vkey_t vkey);
int pk_pkey_mprotect2(int did, void *addr, size_t len, int prot, vkey_t vkey);


/**
 * @brief Protect whole modules with a protection key
 * 
 * This function searches the dynamically loaded modules (see /proc/pid/maps)
 * and protects specified modules with the given protection key. This only
 * affects PT_LOAD segments (typically used for code, data, bss, got, plt)
 * 
 * This function calls pk_pkey_mprotect2(did, ..., vkey) on all matching
 * modules, using the default permission flags from the PT_LOAD segment.
 * 
 * @param did
 *        The domain to which the memory range shall be assigned. Must be
 *        the current or a child domain. Can be @c PK_DOMAIN_CURRENT.
 * @param vkey
 *        The protection key. Can be @c PK_DEFAULT_KEY to specify the
 *        default key of the domain @p did.
 * @param self
 *        If not NULL, only protect module containing this pointer
 * @param module
 *        If not NULL, only protect modules matching this substring.
 *        To protect libc, call with module="libc."
 * 
 * @return
 *      the number of protected modules on success, or -1 on error
 */
int pk_module_protect(int did, vkey_t vkey, const void* self, const char* module);


/**
 * @brief Map a memory range
 * 
 * This function maps a memory range via a call to @c mmap.
 * In addition, it protects the mapped range with the domain's default
 * 
 * @param did
 *        The domain to which the memory range shall be assigned. Must be
 *        the current or a child domain. If omitted, is set to
 *        @c PK_DOMAIN_CURRENT.
 * @param vkey
 *        The protection key. If omitted, is set to @c PK_DEFAULT_KEY to
 *        specify the default key of the domain @p did.
 * @param addr
 *        see @c mmap
 * @param length
 *        see @c mmap
 * @param prot
 *        see @c mmap
 * @param flags
 *        see @c mmap
 * @param fd
 *        see @c mmap
 * @param offset
 *        see @c mmap
 * @return 
 *        0 on success, or -1 on error, and errno is set according to 
 *        @c mmap, or @c pk_pkey_mprotect.
 */
void* pk_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* pk_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* pk_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);


/**
 * @brief Unmap a memory range
 * 
 * This function unmaps a memory range via a call to @c munmap.
 * The memory has to be owned by @p did. 
 *
 * @param did
 *        The domain from which the memory range shall be freed. Must be
 *        the current or a child domain. If omitted, is set to
 *        @c PK_DOMAIN_CURRENT.
 * @param addr
 *        see @c munmap
 * @param len
 *        see @c munmap
 * @return 
 *        0 on success, or -1 on error, and errno is set according to 
 *        @c munmap
 */
int pk_munmap(void* addr, size_t len);
int pk_munmap2(int did, void* addr, size_t len);


/**
 * @brief Protect a memory range
 * 
 * This function protects a memory range via a call to @c mprotect.
 * While this function does not modify protection keys, it verifies
 * that the memory range's protection keys are owned by the calling
 * domain.
 *
 * @param did
 *        The domain from which the memory range shall be protected.
 *        Must be the current or a child domain. If omitted, is set to
 *        @c PK_DOMAIN_CURRENT.
 * @param addr
 *        see @c mprotect
 * @param len
 *        see @c mprotect
 * @param prot
 *        see @c mprotect
 * @return 
 *        0 on success, or -1 on error, and errno is set according to 
 *        @c mprotect
 */
int pk_mprotect(void *addr, size_t len, int prot);
int pk_mprotect2(int did, void *addr, size_t len, int prot);


/**
 * @brief Register a new ecall.
 * 
 * This function registers a new ecall with which another domain can
 * call the specified domain.
 * 
 * @param did
 *        The domain for which a new ecall shall be registered.
 *        If omitted or set to @c PK_DOMAIN_CURRENT, the current domain.
 * @param ecall_id
 *        The positive, unique id of the ecall. If @c PK_ECALL_ANY, the implementation
 *        allocates the next free ecall id.
 * @param entry
 *        The entry point of the ecall
 * @return
 *        the positive ecall_id on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is neither the current domain nor a child domain.
 *        @c EINVAL
 *            if @p entry does not point into the memory of @p did, or
 *            @p ecall_id is invalid.
 *        @c ENOMEM
 *            if there is no more space for registering ecalls
 */
int pk_domain_register_ecall(int ecall_id, void* entry);
int pk_domain_register_ecall2(int did, int ecall_id, void* entry);


/**
 * @brief Permit other domains to invoke ecalls.
 *
 * This function permits other domains to invoke ecalls of the specified
 * domain.
 *
 * @param did
 *        The domain to which ecalls are permitted.
 *        If omitted or set to @c PK_DOMAIN_CURRENT, the current domain.
 * @param caller_did
 *        The domain which is permitted to invoke ecalls of @p did. 
 *        If @c PK_DOMAIN_ANY, any current and future domain is permitted
 *        to invoke ecalls of @p did
 * @param flags
 *        Optional flags for future use. Must be 0 in current implementations.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is neither the current domain nor a child domain.
 *        @c EINVAL
 *            if @p caller_did or @p flags are invalid.
 *        @c ENOMEM
 *            if there is no more space for new callers
 */
int pk_domain_allow_caller(int caller_did, unsigned int flags);
int pk_domain_allow_caller2(int did, int caller_did, unsigned int flags);


/**
 * @brief Load or unload a protection key
 * 
 * This function loads a specific @p vkey for the current domain into the
 * protection register. Depending on the architecture, it might have only
 * a limited number of slots available. In this case, setting a @p vkey
 * to a specific slot invalidates the previous key in this slot. Also,
 * this function can be used to unload a @p vkey.
 * 
 * @param vkey
 *        the protection key, can also be @c PK_DEFAULT_KEY
 * @param slot
 *        if supported by the architecture, loads @p vkey into the
 *        specified slot. If @c PK_SLOT_ANY, the implementation decides
 *        which slot to use. If @c PK_SLOT_NONE, the key is unloaded.
 * @param flags
 *        Optional flags for future use. Must be 0 in current implementations.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EINVAL
 *            if @p slot, @p perm or @p flags is invalid. An implementation can
 *            use this error code to determine the number of available
 *            slots.
 *        @c EACCES
 *            if current domain does not own @p vkey.
 */
int pk_domain_load_key(vkey_t vkey, int slot, unsigned int flags);


/**
 * @brief Create a new thread
 * 
 * This is a wrapper for @c pthread_create. In addition, it ensures that
 * the created thread gets assigned an individual stack for each domain
 * it switches to.
 * 
 * Limitations: The tls is currently not separated across domains.
 * Using it is undefined behavior.
 * 
 * @param thread
 *        see @c pthread_create
 * @param attr
 *        see @c pthread_create
 * @param start_routine
 *        see @c pthread_create
 * @param arg
 *        see @c pthread_create
 * @return
 *        0 on success
 *        @c EAGAIN
 *            see @c pthread_create
 *        @c EINVAL
 *            see @c pthread_create
 *        @c EPERM
 *            see @c pthread_create
 */
int pk_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine) (void *), void *arg);


/**
 * @brief Terminate the current thread
 * 
 * This is a wrapper for @c pthread_exit.
 */
int pk_pthread_exit(void *retval);


/**
 * @brief Register a userspace exception handler
 * 
 * This function registers an exception handler in user space. This is
 * similar to signals.
 * Whenever a vkey-related exception occurs, the pk library first tries
 * to resolve the exception and reload the missing vkey. If the current
 * domain does not own an appropriate vkey, the exception is forwarded
 * to the registered handler. Currently, this function is not allowed to
 * return, so the only appropriate action is to terminate the program,
 * or resume execution at a previous point with setjmp/longjmp.
 */
int pk_register_exception_handler(void (*handler)(void*));


/**
 * @brief Get current domain ID
 * 
 * @return
 *        The domain id @p did of the current domain.
 */
int pk_current_did(void);


typedef void (*sighandler_t)(int);

/**
 * @brief Register signal handlers
 * 
 * These functions register signal handlers via @c signal or
 * @c sigaction, respectively
 * 
 * Limitations: Signal support is currently unsafe. For compatibility, 
 * the signal handler is given full protection key access.
 * 
 */
sighandler_t pk_signal(int signum, sighandler_t handler);
int          pk_sigaction(int signum, const struct sigaction *act,
                          struct sigaction *oldact);

//------------------------------------------------------------------------------
// PK debug functions
//------------------------------------------------------------------------------

int  pk_simple_api_call(int a, int b, int c, int d, int e, int f);
void pk_print_debug_info(void);
void pk_print_current_reg(void);
void pk_debug_usercheck(int expected_did);


#ifdef __cplusplus
}

#include "pku_wrapper.h"

#endif

#endif // __ASSEMBLY__
