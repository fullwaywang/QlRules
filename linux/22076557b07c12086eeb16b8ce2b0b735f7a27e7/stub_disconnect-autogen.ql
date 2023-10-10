/**
 * @name linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-stub_disconnect
 * @id cpp/linux/22076557b07c12086eeb16b8ce2b0b735f7a27e7/stub_disconnect
 * @description linux-22076557b07c12086eeb16b8ce2b0b735f7a27e7-stub_disconnect 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vsdev_402) {
	exists(GotoStmt target_0 |
		target_0.toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vsdev_402)
}

predicate func_3(Function func) {
	exists(LabelStmt target_3 |
		target_3.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_3))
}

predicate func_4(Variable vbusid_priv_404, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("put_busid_priv")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbusid_priv_404
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_4))
}

predicate func_5(Variable vsdev_402) {
	exists(ReturnStmt target_5 |
		target_5.toString() = "return ..."
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vsdev_402)
}

predicate func_9(Variable vbusid_priv_404) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="status"
		and target_9.getQualifier().(VariableAccess).getTarget()=vbusid_priv_404)
}

from Function func, Variable vsdev_402, Variable vbusid_priv_404, Variable vrc_405
where
not func_0(vsdev_402)
and not func_3(func)
and not func_4(vbusid_priv_404, func)
and func_5(vsdev_402)
and vsdev_402.getType().hasName("stub_device *")
and vbusid_priv_404.getType().hasName("bus_id_priv *")
and func_9(vbusid_priv_404)
and vrc_405.getType().hasName("int")
and vsdev_402.getParentScope+() = func
and vbusid_priv_404.getParentScope+() = func
and vrc_405.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
