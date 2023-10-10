/**
 * @name redis-c04082cf138f1f51cedf05ee9ad36fb6763cafc6-xgroupCommand
 * @id cpp/redis/c04082cf138f1f51cedf05ee9ad36fb6763cafc6/xgroupCommand
 * @description redis-c04082cf138f1f51cedf05ee9ad36fb6763cafc6-xgroupCommand CVE-2018-12453
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vo_1578, Parameter vc_1562, EqualityOperation target_1, ArrayExpr target_2, ArrayExpr target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("checkType")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1562
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vo_1578
		and target_0.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="6"
		and target_0.getParent().(IfStmt).getThen() instanceof ReturnStmt
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vo_1578, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vo_1578
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen() instanceof ReturnStmt
}

predicate func_2(Parameter vc_1562, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1562
		and target_2.getArrayOffset().(Literal).getValue()="2"
}

predicate func_3(Parameter vc_1562, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1562
		and target_3.getArrayOffset().(Literal).getValue()="3"
}

from Function func, Variable vo_1578, Parameter vc_1562, EqualityOperation target_1, ArrayExpr target_2, ArrayExpr target_3
where
not func_0(vo_1578, vc_1562, target_1, target_2, target_3)
and func_1(vo_1578, target_1)
and func_2(vc_1562, target_2)
and func_3(vc_1562, target_3)
and vo_1578.getType().hasName("robj *")
and vc_1562.getType().hasName("client *")
and vo_1578.getParentScope+() = func
and vc_1562.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
