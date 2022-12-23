/**
 * @name linux-6ff7b060535e87c2ae14dd8548512abfdda528fb-__mdiobus_register
 * @id cpp/linux/6ff7b060535e87c2ae14dd8548512abfdda528fb/__mdiobus_register
 * @description linux-6ff7b060535e87c2ae14dd8548512abfdda528fb-__mdiobus_register 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vbus_360) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbus_360
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_1(Variable verr_363) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("put_device")
		and target_1.getExpr().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_363)
}

from Function func, Variable verr_363, Parameter vbus_360
where
func_0(vbus_360)
and func_1(verr_363)
and verr_363.getType().hasName("int")
and vbus_360.getType().hasName("mii_bus *")
and verr_363.getParentScope+() = func
and vbus_360.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
