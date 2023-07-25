/**
 * @name expat-9f93e8036e842329863bf20395b8fb8f73834d9e-lookup
 * @id cpp/expat/9f93e8036e842329863bf20395b8fb8f73834d9e/lookup
 * @description expat-9f93e8036e842329863bf20395b8fb8f73834d9e-expat/lib/xmlparse.c-lookup CVE-2022-22822
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnewPower_6794, BinaryBitwiseOperation target_2, BinaryBitwiseOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnewPower_6794
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="64"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vnewSize_6795, BinaryBitwiseOperation target_2, SubExpr target_4, MulExpr target_5) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnewSize_6795
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="2305843009213693951"
		and target_1.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_4.getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(BinaryBitwiseOperation target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="used"
		and target_2.getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="power"
		and target_2.getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_3(Variable vnewPower_6794, BinaryBitwiseOperation target_3) {
		target_3.getLeftOperand().(Literal).getValue()="1"
		and target_3.getRightOperand().(VariableAccess).getTarget()=vnewPower_6794
}

predicate func_4(Variable vnewSize_6795, SubExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vnewSize_6795
		and target_4.getRightOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vnewSize_6795, MulExpr target_5) {
		target_5.getLeftOperand().(VariableAccess).getTarget()=vnewSize_6795
		and target_5.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getRightOperand().(SizeofTypeOperator).getValue()="8"
}

from Function func, Variable vnewPower_6794, Variable vnewSize_6795, BinaryBitwiseOperation target_2, BinaryBitwiseOperation target_3, SubExpr target_4, MulExpr target_5
where
not func_0(vnewPower_6794, target_2, target_3)
and not func_1(vnewSize_6795, target_2, target_4, target_5)
and func_2(target_2)
and func_3(vnewPower_6794, target_3)
and func_4(vnewSize_6795, target_4)
and func_5(vnewSize_6795, target_5)
and vnewPower_6794.getType().hasName("unsigned char")
and vnewSize_6795.getType().hasName("size_t")
and vnewPower_6794.getParentScope+() = func
and vnewSize_6795.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
