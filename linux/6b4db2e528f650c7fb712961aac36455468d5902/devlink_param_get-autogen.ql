/**
 * @name linux-6b4db2e528f650c7fb712961aac36455468d5902-devlink_param_get
 * @id cpp/linux/6b4db2e528f650c7fb712961aac36455468d5902/devlink_param_get
 * @description linux-6b4db2e528f650c7fb712961aac36455468d5902-devlink_param_get 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdevlink_5146) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="reload_failed"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdevlink_5146
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-95"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="95")
}

predicate func_1(Parameter vparam_5147) {
	exists(NotExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="get"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_5147
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-95"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="95")
}

from Function func, Parameter vparam_5147, Parameter vdevlink_5146
where
not func_0(vdevlink_5146)
and func_1(vparam_5147)
and vparam_5147.getType().hasName("const devlink_param *")
and vdevlink_5146.getType().hasName("devlink *")
and vparam_5147.getParentScope+() = func
and vdevlink_5146.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
