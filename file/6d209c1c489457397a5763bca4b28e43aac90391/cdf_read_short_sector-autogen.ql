/**
 * @name file-6d209c1c489457397a5763bca4b28e43aac90391-cdf_read_short_sector
 * @id cpp/file/6d209c1c489457397a5763bca4b28e43aac90391/cdf-read-short-sector
 * @description file-6d209c1c489457397a5763bca4b28e43aac90391-src/cdf.c-cdf_read_short_sector CVE-2014-0236
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_350, Variable vpos_353, BlockStmt target_2, EqualityOperation target_3, ExprStmt target_4, PointerArithmeticOperation target_5) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vpos_353
		and target_0.getAnOperand().(VariableAccess).getTarget()=vlen_350
		and target_0.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=vpos_353
		and target_0.getParent().(GTExpr).getLesserOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getParent().(GTExpr).getLesserOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="h_sec_size_p2"
		and target_0.getParent().(GTExpr).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="sst_len"
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpos_353, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vpos_353
		and target_1.getParent().(GTExpr).getLesserOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getParent().(GTExpr).getLesserOperand().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="h_sec_size_p2"
		and target_1.getParent().(GTExpr).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="sst_len"
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(EmptyStmt).toString() = ";"
		and target_2.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_3(Parameter vlen_350, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vlen_350
}

predicate func_4(Parameter vlen_350, Variable vpos_353, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sst_tab"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpos_353
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_350
}

predicate func_5(Variable vpos_353, PointerArithmeticOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="sst_tab"
		and target_5.getAnOperand().(VariableAccess).getTarget()=vpos_353
}

from Function func, Parameter vlen_350, Variable vpos_353, VariableAccess target_1, BlockStmt target_2, EqualityOperation target_3, ExprStmt target_4, PointerArithmeticOperation target_5
where
not func_0(vlen_350, vpos_353, target_2, target_3, target_4, target_5)
and func_1(vpos_353, target_2, target_1)
and func_2(target_2)
and func_3(vlen_350, target_3)
and func_4(vlen_350, vpos_353, target_4)
and func_5(vpos_353, target_5)
and vlen_350.getType().hasName("size_t")
and vpos_353.getType().hasName("size_t")
and vlen_350.getParentScope+() = func
and vpos_353.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
