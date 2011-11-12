
void microblaze_linux_supply_gregset (const struct regset *regset,
				struct regcache *regcache,
				int regnum, const void *gregs_buf, size_t len);

void microblaze_linux_collect_gregset (const struct regset *regset,
				const struct regcache *regcache,
				int regnum, void *gregs_buf, size_t len);


void microblaze_linux_supply_fpregset (const struct regset *regset,
				struct regcache *regcache,
				int regnum, const void *fpregs_buf, size_t len);

void microblaze_linux_collect_fpregset (const struct regset *regset,
				const struct regcache *regcache,
				int regnum, void *fpregs_buf, size_t len);

