/**
 * @name linux-7d63fb3af87aa67aa7d24466e792f9d7c57d8e79-swiotlb_late_init_with_default_size
 * @id cpp/linux/7d63fb3af87aa67aa7d24466e792f9d7c57d8e79/swiotlb-late-init-with-default-size
 * @description linux-7d63fb3af87aa67aa7d24466e792f9d7c57d8e79-swiotlb_late_init_with_default_size NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="4Warning: only able to allocate %ld MB for software IO TLB\n"
		and not target_0.getValue()="4software IO TLB: only able to allocate %ld MB\n"
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
