/**
 * @name libarchive-fa7438a0ff4033e4741c807394a9af6207940d71-atol10
 * @id cpp/libarchive/fa7438a0ff4033e4741c807394a9af6207940d71/atol10
 * @description libarchive-fa7438a0ff4033e4741c807394a9af6207940d71-libarchive/archive_read_support_format_xar.c-atol10 CVE-2017-14166
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vchar_cnt_1038, LogicalAndExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchar_cnt_1038
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vchar_cnt_1038, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vchar_cnt_1038
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

from Function func, Parameter vchar_cnt_1038, LogicalAndExpr target_1
where
not func_0(vchar_cnt_1038, target_1, func)
and func_1(vchar_cnt_1038, target_1)
and vchar_cnt_1038.getType().hasName("size_t")
and vchar_cnt_1038.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
