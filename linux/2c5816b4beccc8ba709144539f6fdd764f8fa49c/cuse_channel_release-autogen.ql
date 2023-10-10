/**
 * @name linux-2c5816b4beccc8ba709144539f6fdd764f8fa49c-cuse_channel_release
 * @id cpp/linux/2c5816b4beccc8ba709144539f6fdd764f8fa49c/cuse_channel_release
 * @description linux-2c5816b4beccc8ba709144539f6fdd764f8fa49c-cuse_channel_release 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vcc_537, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("fuse_conn_put")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="fc"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcc_537
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Variable vcc_537) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="cdev"
		and target_1.getQualifier().(VariableAccess).getTarget()=vcc_537)
}

from Function func, Variable vcc_537
where
not func_0(vcc_537, func)
and vcc_537.getType().hasName("cuse_conn *")
and func_1(vcc_537)
and vcc_537.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
