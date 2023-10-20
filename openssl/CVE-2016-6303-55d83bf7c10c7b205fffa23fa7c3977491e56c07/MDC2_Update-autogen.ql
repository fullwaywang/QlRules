/**
 * @name openssl-55d83bf7c10c7b205fffa23fa7c3977491e56c07-MDC2_Update
 * @id cpp/openssl/55d83bf7c10c7b205fffa23fa7c3977491e56c07/MDC2-Update
 * @description openssl-55d83bf7c10c7b205fffa23fa7c3977491e56c07-crypto/mdc2/mdc2dgst.c-MDC2_Update CVE-2016-6303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_41, BlockStmt target_5, EqualityOperation target_6, AddressOfExpr target_7) {
	exists(SubExpr target_0 |
		target_0.getLeftOperand() instanceof Literal
		and target_0.getRightOperand().(VariableAccess).getTarget()=vi_41
		and target_0.getParent().(LTExpr).getLesserOperand() instanceof AddExpr
		and target_0.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_5
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(VariableAccess).getLocation())
		and target_0.getRightOperand().(VariableAccess).getLocation().isBefore(target_7.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_41, VariableAccess target_1) {
		target_1.getTarget()=vi_41
}

predicate func_2(Parameter vlen_39, VariableAccess target_2) {
		target_2.getTarget()=vlen_39
}

predicate func_4(Parameter vlen_39, Variable vi_41, BlockStmt target_5, AddExpr target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vi_41
		and target_4.getAnOperand().(VariableAccess).getTarget()=vlen_39
		and target_4.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vlen_39, Variable vi_41, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_41
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_39
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num"
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vlen_39
}

predicate func_6(Variable vi_41, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vi_41
		and target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Variable vi_41, AddressOfExpr target_7) {
		target_7.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_41
}

from Function func, Parameter vlen_39, Variable vi_41, VariableAccess target_1, VariableAccess target_2, AddExpr target_4, BlockStmt target_5, EqualityOperation target_6, AddressOfExpr target_7
where
not func_0(vi_41, target_5, target_6, target_7)
and func_1(vi_41, target_1)
and func_2(vlen_39, target_2)
and func_4(vlen_39, vi_41, target_5, target_4)
and func_5(vlen_39, vi_41, target_5)
and func_6(vi_41, target_6)
and func_7(vi_41, target_7)
and vlen_39.getType().hasName("size_t")
and vi_41.getType().hasName("size_t")
and vlen_39.getParentScope+() = func
and vi_41.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
