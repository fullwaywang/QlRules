/**
 * @name zlib-eff308af425b67093bab25f80f1ae950166bece1-inflate
 * @id cpp/zlib/eff308af425b67093bab25f80f1ae950166bece1/inflate
 * @description zlib-eff308af425b67093bab25f80f1ae950166bece1-inflate.c-inflate CVE-2022-37434
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstate_627, Variable vlen_638, BlockStmt target_3, ExprStmt target_4, LogicalAndExpr target_2, ExprStmt target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_638
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="extra_max"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="head"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_0.getParent().(IfStmt).getThen()=target_3
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vstate_627, Variable vlen_638, LogicalAndExpr target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_638
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="extra_len"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="head"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vstate_627, BlockStmt target_3, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="head"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="extra"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="head"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_3
}

predicate func_3(Variable vstate_627, Variable vlen_638, BlockStmt target_3) {
		target_3.getStmt(0) instanceof ExprStmt
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="extra"
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="head"
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_638
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_638
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="extra_max"
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="head"
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="extra_max"
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="head"
		and target_3.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen_638
}

predicate func_4(Variable vstate_627, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
}

predicate func_5(Variable vstate_627, Variable vlen_638, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_5.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_5.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vlen_638
}

from Function func, Variable vstate_627, Variable vlen_638, ExprStmt target_1, LogicalAndExpr target_2, BlockStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vstate_627, vlen_638, target_3, target_4, target_2, target_5)
and func_1(vstate_627, vlen_638, target_2, target_1)
and func_2(vstate_627, target_3, target_2)
and func_3(vstate_627, vlen_638, target_3)
and func_4(vstate_627, target_4)
and func_5(vstate_627, vlen_638, target_5)
and vstate_627.getType().hasName("inflate_state *")
and vlen_638.getType().hasName("unsigned int")
and vstate_627.getParentScope+() = func
and vlen_638.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
