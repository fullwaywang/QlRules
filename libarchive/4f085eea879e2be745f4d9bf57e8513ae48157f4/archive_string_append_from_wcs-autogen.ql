/**
 * @name libarchive-4f085eea879e2be745f4d9bf57e8513ae48157f4-archive_string_append_from_wcs
 * @id cpp/libarchive/4f085eea879e2be745f4d9bf57e8513ae48157f4/archive-string-append-from-wcs
 * @description libarchive-4f085eea879e2be745f4d9bf57e8513ae48157f4-libarchive/archive_string.c-archive_string_append_from_wcs CVE-2020-21674
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_772, LogicalAndExpr target_2) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand() instanceof MulExpr
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("__ctype_get_mb_cur_max")
		and target_0.getThen().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_772
		and target_0.getThen().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_0.getElse().(FunctionCall).getTarget().hasName("__ctype_get_mb_cur_max")
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlen_772, MulExpr target_1) {
		target_1.getLeftOperand().(VariableAccess).getTarget()=vlen_772
		and target_1.getRightOperand().(Literal).getValue()="2"
}

predicate func_2(Parameter vlen_772, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_772
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

from Function func, Parameter vlen_772, MulExpr target_1, LogicalAndExpr target_2
where
not func_0(vlen_772, target_2)
and func_1(vlen_772, target_1)
and func_2(vlen_772, target_2)
and vlen_772.getType().hasName("size_t")
and vlen_772.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
