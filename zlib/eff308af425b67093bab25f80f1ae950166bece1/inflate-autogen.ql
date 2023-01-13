/**
 * @name zlib-eff308af425b67093bab25f80f1ae950166bece1-inflate
 * @id cpp/zlib/eff308af425b67093bab25f80f1ae950166bece1/inflate
 * @description zlib-eff308af425b67093bab25f80f1ae950166bece1-inflate CVE-2022-37434
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstate_627, Variable vnext_628, Variable vcopy_634, Variable vlen_638) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_638
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="extra_max"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="head"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="extra"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlen_638
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnext_628
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(VariableAccess).getTarget()=vcopy_634)
}

predicate func_3(Variable vstate_627) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="length"
		and target_3.getQualifier().(VariableAccess).getTarget()=vstate_627)
}

predicate func_4(Variable vstate_627, Variable vlen_638) {
	exists(BinaryBitwiseOperation target_4 |
		target_4.getLeftOperand().(Literal).getValue()="1"
		and target_4.getRightOperand().(VariableAccess).getTarget()=vlen_638
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dmax"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_627)
}

from Function func, Variable vstate_627, Variable vnext_628, Variable vcopy_634, Variable vlen_638
where
not func_0(vstate_627, vnext_628, vcopy_634, vlen_638)
and vstate_627.getType().hasName("inflate_state *")
and func_3(vstate_627)
and vnext_628.getType().hasName("unsigned char *")
and vcopy_634.getType().hasName("unsigned int")
and vlen_638.getType().hasName("unsigned int")
and func_4(vstate_627, vlen_638)
and vstate_627.getParentScope+() = func
and vnext_628.getParentScope+() = func
and vcopy_634.getParentScope+() = func
and vlen_638.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
