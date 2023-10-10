/**
 * @name linux-8e20cf2bce122ce9262d6034ee5d5b76fbb92f96-aiptek_probe
 * @id cpp/linux/8e20cf2bce122ce9262d6034ee5d5b76fbb92f96/aiptek_probe
 * @description linux-8e20cf2bce122ce9262d6034ee5d5b76fbb92f96-aiptek_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_3(Variable verr_1700, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition() instanceof EqualityOperation
		and target_3.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_1700
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_3.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(64)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(64).getFollowingStmt()=target_3))
}

predicate func_8(Parameter vintf_1685) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="dev"
		and target_8.getQualifier().(VariableAccess).getTarget()=vintf_1685)
}

from Function func, Parameter vintf_1685, Variable vi_1691, Variable vspeeds_1692, Variable verr_1700
where
not func_3(verr_1700, func)
and vintf_1685.getType().hasName("usb_interface *")
and func_8(vintf_1685)
and vi_1691.getType().hasName("int")
and vspeeds_1692.getType().hasName("int[]")
and verr_1700.getType().hasName("int")
and vintf_1685.getParentScope+() = func
and vi_1691.getParentScope+() = func
and vspeeds_1692.getParentScope+() = func
and verr_1700.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
