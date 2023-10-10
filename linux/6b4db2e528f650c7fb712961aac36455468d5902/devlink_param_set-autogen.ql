/**
 * @name linux-6b4db2e528f650c7fb712961aac36455468d5902-devlink_param_set
 * @id cpp/linux/6b4db2e528f650c7fb712961aac36455468d5902/devlink_param_set
 * @description linux-6b4db2e528f650c7fb712961aac36455468d5902-devlink_param_set 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdevlink_5155) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="reload_failed"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdevlink_5155
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-95"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="95")
}

predicate func_1(Parameter vparam_5156) {
	exists(NotExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="set"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_5156
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-95"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="95")
}

from Function func, Parameter vparam_5156, Parameter vdevlink_5155
where
not func_0(vdevlink_5155)
and func_1(vparam_5156)
and vparam_5156.getType().hasName("const devlink_param *")
and vdevlink_5155.getType().hasName("devlink *")
and vparam_5156.getParentScope+() = func
and vdevlink_5155.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
