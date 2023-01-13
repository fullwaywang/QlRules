/**
 * @name libexpat-c4bf96bb51dd2a1b0e185374362ee136fe2c9d7f-entityValueInitProcessor
 * @id cpp/libexpat/c4bf96bb51dd2a1b0e185374362ee136fe2c9d7f/entityValueInitProcessor
 * @description libexpat-c4bf96bb51dd2a1b0e185374362ee136fe2c9d7f-entityValueInitProcessor CVE-2017-9233
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnextPtr_3926, Variable vtok_3928, Variable vnext_3930) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtok_3928
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="29"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextPtr_3926
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnext_3930
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtok_3928
		and target_0.getParent().(IfStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="12")
}

predicate func_3(Parameter vnextPtr_3926, Variable vnext_3930) {
	exists(PointerDereferenceExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vnextPtr_3926
		and target_3.getParent().(AssignExpr).getLValue() = target_3
		and target_3.getParent().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnext_3930)
}

predicate func_4(Variable vtok_3928) {
	exists(EqualityOperation target_4 |
		target_4.getAnOperand().(VariableAccess).getTarget()=vtok_3928
		and target_4.getAnOperand().(Literal).getValue()="14")
}

predicate func_5(Parameter vnextPtr_3926, Variable vnext_3930) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnextPtr_3926
		and target_5.getRValue().(VariableAccess).getTarget()=vnext_3930)
}

from Function func, Parameter vnextPtr_3926, Variable vtok_3928, Variable vnext_3930
where
not func_0(vnextPtr_3926, vtok_3928, vnext_3930)
and vnextPtr_3926.getType().hasName("const char **")
and func_3(vnextPtr_3926, vnext_3930)
and vtok_3928.getType().hasName("int")
and func_4(vtok_3928)
and vnext_3930.getType().hasName("const char *")
and func_5(vnextPtr_3926, vnext_3930)
and vnextPtr_3926.getParentScope+() = func
and vtok_3928.getParentScope+() = func
and vnext_3930.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
