/**
 * @name redis-6c25c6b7da116e110e89a5db45eeae743879e7ea-appendCommand
 * @id cpp/redis/6c25c6b7da116e110e89a5db45eeae743879e7ea/appendCommand
 * @description redis-6c25c6b7da116e110e89a5db45eeae743879e7ea-appendCommand CVE-2022-35977
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vo_692, FunctionCall target_0) {
		target_0.getTarget().hasName("stringObjectLen")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vo_692
}

predicate func_1(Variable vappend_692, FunctionCall target_1) {
		target_1.getTarget().hasName("sdslen")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vappend_692
}

predicate func_2(Variable vtotlen_691, EqualityOperation target_4, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtotlen_691
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand() instanceof FunctionCall
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand() instanceof FunctionCall
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_3(Variable vtotlen_691, ExprStmt target_2, VariableAccess target_3) {
		target_3.getTarget()=vtotlen_691
		and target_3.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("checkStringLength")
		and target_3.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("client *")
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getLocation())
}

predicate func_4(Variable vo_692, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vo_692
		and target_4.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vtotlen_691, Variable vo_692, Variable vappend_692, FunctionCall target_0, FunctionCall target_1, ExprStmt target_2, VariableAccess target_3, EqualityOperation target_4
where
func_0(vo_692, target_0)
and func_1(vappend_692, target_1)
and func_2(vtotlen_691, target_4, target_2)
and func_3(vtotlen_691, target_2, target_3)
and func_4(vo_692, target_4)
and vtotlen_691.getType().hasName("size_t")
and vo_692.getType().hasName("robj *")
and vappend_692.getType().hasName("robj *")
and vtotlen_691.getParentScope+() = func
and vo_692.getParentScope+() = func
and vappend_692.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
