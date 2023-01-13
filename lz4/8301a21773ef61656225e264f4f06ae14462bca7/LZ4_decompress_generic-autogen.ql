/**
 * @name lz4-8301a21773ef61656225e264f4f06ae14462bca7-LZ4_decompress_generic
 * @id cpp/lz4/8301a21773ef61656225e264f4f06ae14462bca7/LZ4-decompress-generic
 * @description lz4-8301a21773ef61656225e264f4f06ae14462bca7-LZ4_decompress_generic CVE-2021-3520
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voutputSize_1742) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voutputSize_1742
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_1(Parameter vsrc_1739) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vsrc_1739
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

from Function func, Parameter voutputSize_1742, Parameter vsrc_1739
where
not func_0(voutputSize_1742)
and func_1(vsrc_1739)
and voutputSize_1742.getType().hasName("int")
and vsrc_1739.getType().hasName("const char *const")
and voutputSize_1742.getParentScope+() = func
and vsrc_1739.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
