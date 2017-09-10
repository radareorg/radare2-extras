/* Sample r2k kext for XNU -- pancake@nopcode.org */

#include <sys/systm.h>
#include <mach/mach_types.h>
 
kern_return_t r2k_start (kmod_info_t * ki, void * d) {
    printf ("r2k has started.\n");
    return KERN_SUCCESS;
}
 
kern_return_t r2k_stop (kmod_info_t * ki, void * d) {
    printf ("r2k has stopped.\n");
    return KERN_SUCCESS;
}
