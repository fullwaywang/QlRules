/**
 * @name ceph-74d99057a5146755e737c479850f87fd0e3b6868-resume
 * @id cpp/ceph/74d99057a5146755e737c479850f87fd0e3b6868/resume
 * @description ceph-74d99057a5146755e737c479850f87fd0e3b6868-ldo.c-resume CVE-2021-43519
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vL_757, EqualityOperation target_2, ExprStmt target_3, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ccall")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_757
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-1"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Parameter vL_757, EqualityOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("luaE_incCstack")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vL_757
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vL_757, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="status"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_757
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vL_757, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vL_757
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vL_757, Literal target_0, ExprStmt target_1, EqualityOperation target_2, ExprStmt target_3
where
func_0(vL_757, target_2, target_3, target_0)
and func_1(vL_757, target_2, target_1)
and func_2(vL_757, target_2)
and func_3(vL_757, target_3)
and vL_757.getType().hasName("lua_State *")
and vL_757.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
