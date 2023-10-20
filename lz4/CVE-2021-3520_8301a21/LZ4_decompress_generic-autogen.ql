/**
 * @name lz4-8301a21773ef61656225e264f4f06ae14462bca7-LZ4_decompress_generic
 * @id cpp/lz4/8301a21773ef61656225e264f4f06ae14462bca7/LZ4-decompress-generic
 * @description lz4-8301a21773ef61656225e264f4f06ae14462bca7-lib/lz4.c-LZ4_decompress_generic CVE-2021-3520
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voutputSize_1742, BlockStmt target_2, PointerArithmeticOperation target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voutputSize_1742
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsrc_1739, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vsrc_1739
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_3(Parameter voutputSize_1742, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=voutputSize_1742
}

from Function func, Parameter voutputSize_1742, Parameter vsrc_1739, EqualityOperation target_1, BlockStmt target_2, PointerArithmeticOperation target_3
where
not func_0(voutputSize_1742, target_2, target_3)
and func_1(vsrc_1739, target_2, target_1)
and func_2(target_2)
and func_3(voutputSize_1742, target_3)
and voutputSize_1742.getType().hasName("int")
and vsrc_1739.getType().hasName("const char *const")
and voutputSize_1742.getParentScope+() = func
and vsrc_1739.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
