/**
 * @name linux-36e4ad0316c017d5b271378ed9a1c9a4b77fab5f-gfs2_clear_rgrpd
 * @id cpp/linux/36e4ad0316c017d5b271378ed9a1c9a4b77fab5f/gfs2-clear-rgrpd
 * @description linux-36e4ad0316c017d5b271378ed9a1c9a4b77fab5f-gfs2_clear_rgrpd 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrgd_706) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rd_bits"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrgd_706
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_1(Variable vrgd_706) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="rd_bits"
		and target_1.getQualifier().(VariableAccess).getTarget()=vrgd_706)
}

from Function func, Variable vrgd_706
where
not func_0(vrgd_706)
and vrgd_706.getType().hasName("gfs2_rgrpd *")
and func_1(vrgd_706)
and vrgd_706.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
