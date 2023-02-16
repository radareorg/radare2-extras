
/* Foreign IO device hook that returns an unique name identifying the
   kind of device.  */

static const char * iod_get_if_name (void) {
	return "R2";
}

/* Foreign IO device hook that recognizes whether a given IO space
   handler refer to this kind of device, and normalizes it for further
   use.  */

static char * iod_handler_normalize (const char *handler, uint64_t flags, int *error) {
	char *new_handler = NULL;

	if (strcmp (handler, "<r2>") == 0)
		new_handler = strdup (handler);
	if (error)
		*error = PK_IOD_OK;

	return new_handler;
}

/* Foreign IO device hook that opens a new device.  */

static bool iod_opened_p = false;

static void * iod_open (const char *handler, uint64_t flags, int *error, void *data) {
	iod_opened_p = true;
	return &iod_opened_p;
}

/* Foreign IO device hook that reads data from a device.  */

static int iod_pread (void *dev, void *buf, size_t count, pk_iod_off offset) {
	if (Gcore == NULL) {
		R_LOG_ERROR ("Cannot find the r2 core");
		return -1;
	}
	int ret = r_io_read_at (Gcore->io, offset, buf, count);
	return ret == -1 ? PK_IOD_ERROR : PK_IOD_OK;
}

/* Foreign IO device hook that writes data to a device.  */

static int iod_pwrite (void *dev, const void *buf, size_t count, pk_iod_off offset) {
	int ret = r_io_write_at (Gcore->io, offset, (ut8*) buf, count);
	// int ret = target_write_memory (offset, (ut8*) buf, count);
	return ret == -1 ? PK_IOD_ERROR : PK_IOD_OK;
}

/* Foreign IO device hook that returns the flags of an IO device. */

static uint64_t iod_get_flags (void *dev) {
	return PK_IOS_F_READ | PK_IOS_F_WRITE;
}

/* Foreign IO device hook that returns the size of an IO device, in
   bytes.  */

static pk_iod_off iod_size (void *dev) {
	return Gcore->anal->arch->cfg->bits==64?UT64_MAX: UT32_MAX;
}

/* Foreign IO device hook that flushes an IO device.  */
static int iod_flush (void *dev, pk_iod_off offset) {
	/* Do nothing here.  */
	return PK_OK;
}

/* Foreign IO device hook that closes a given device.  */
static int iod_close (void *dev) {
	iod_opened_p = 0;
	return PK_OK;
}

/* Implementation of the poke foreign IO device interface, that uses
   the hooks defined above.  */
static struct pk_iod_if iod_if = {
	iod_get_if_name,
	iod_handler_normalize,
	iod_open,
	iod_close,
	iod_pread,
	iod_pwrite,
	iod_get_flags,
	iod_size,
	iod_flush
};
