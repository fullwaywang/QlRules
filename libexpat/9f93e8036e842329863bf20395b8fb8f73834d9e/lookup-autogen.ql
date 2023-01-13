/**
 * @name libexpat-9f93e8036e842329863bf20395b8fb8f73834d9e-lookup
 * @id cpp/libexpat/9f93e8036e842329863bf20395b8fb8f73834d9e/lookup
 * @description libexpat-9f93e8036e842329863bf20395b8fb8f73834d9e-lookup CVE-2022-22825
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtable_6760, Variable vnewPower_6794) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnewPower_6794
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="64"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="used"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_6760
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="power"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_6760
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_2(Parameter vtable_6760, Variable vnewSize_6795) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnewSize_6795
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="2305843009213693951"
		and target_2.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="used"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_6760
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="power"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_6760
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_4(Variable vnewSize_6795) {
	exists(SubExpr target_4 |
		target_4.getLeftOperand().(VariableAccess).getTarget()=vnewSize_6795
		and target_4.getRightOperand().(Literal).getValue()="1")
}

from Function func, Parameter vtable_6760, Variable vnewPower_6794, Variable vnewSize_6795
where
not func_0(vtable_6760, vnewPower_6794)
and not func_2(vtable_6760, vnewSize_6795)
and vtable_6760.getType().hasName("HASH_TABLE *")
and vnewPower_6794.getType().hasName("unsigned char")
and vnewSize_6795.getType().hasName("size_t")
and func_4(vnewSize_6795)
and vtable_6760.getParentScope+() = func
and vnewPower_6794.getParentScope+() = func
and vnewSize_6795.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
