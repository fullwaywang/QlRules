/**
 * @name linux-dcde237319e626d1ec3c9d8b7613032f0fd4663a-ksys_mmap_pgoff
 * @id cpp/linux/dcde237319e626d1ec3c9d8b7613032f0fd4663a/ksys_mmap_pgoff
 * @description linux-dcde237319e626d1ec3c9d8b7613032f0fd4663a-ksys_mmap_pgoff 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vaddr_1553, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vaddr_1553
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vaddr_1553
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vaddr_1553
where
func_0(vaddr_1553, func)
and vaddr_1553.getType().hasName("unsigned long")
and vaddr_1553.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
