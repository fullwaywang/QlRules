/**
 * @name jbig2dec-9d2c4f3bdb0bd003deae788e7187c0f86e624544-jbig2_decode_mmr_line
 * @id cpp/jbig2dec/9d2c4f3bdb0bd003deae788e7187c0f86e624544/jbig2-decode-mmr-line
 * @description jbig2dec-9d2c4f3bdb0bd003deae788e7187c0f86e624544-jbig2_mmr.c-jbig2_decode_mmr_line CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable va0_836, ReturnStmt target_4, LogicalOrExpr target_5, ExprStmt target_6) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=va0_836
		and target_1.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_836
		and target_1.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Variable va0_836, VariableAccess target_2) {
		target_2.getTarget()=va0_836
}

predicate func_3(Variable va0_836, ReturnStmt target_4, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=va0_836
		and target_3.getGreaterOperand() instanceof Literal
		and target_3.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_4(ReturnStmt target_4) {
		target_4.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_5(Variable va0_836, LogicalOrExpr target_5) {
		target_5.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_836
		and target_5.getAnOperand() instanceof RelationalOperation
}

predicate func_6(Variable va0_836, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("jbig2_set_bits")
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_836
		and target_6.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="2"
}

from Function func, Variable va0_836, Literal target_0, VariableAccess target_2, RelationalOperation target_3, ReturnStmt target_4, LogicalOrExpr target_5, ExprStmt target_6
where
func_0(func, target_0)
and not func_1(va0_836, target_4, target_5, target_6)
and func_2(va0_836, target_2)
and func_3(va0_836, target_4, target_3)
and func_4(target_4)
and func_5(va0_836, target_5)
and func_6(va0_836, target_6)
and va0_836.getType().hasName("uint32_t")
and va0_836.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
