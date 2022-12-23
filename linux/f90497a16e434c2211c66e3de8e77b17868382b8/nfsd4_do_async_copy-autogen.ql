/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_do_async_copy
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-do-async-copy
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_do_async_copy 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnfserr_1763, Variable vfilp_1766) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnfserr_1763
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getValue()="1797718016"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfilp_1766)
}

from Function func, Variable vnfserr_1763, Variable vfilp_1766
where
func_0(vnfserr_1763, vfilp_1766)
and vnfserr_1763.getType().hasName("__be32")
and vfilp_1766.getType().hasName("file *")
and vnfserr_1763.getParentScope+() = func
and vfilp_1766.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
