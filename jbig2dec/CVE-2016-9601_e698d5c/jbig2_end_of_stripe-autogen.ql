/**
 * @name jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_end_of_stripe
 * @id cpp/jbig2dec/e698d5c11d27212aa1098bc5b1673a3378563092/jbig2-end-of-stripe
 * @description jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_page.c-jbig2_end_of_stripe CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vsegment_data_155, Variable vend_row_158) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vend_row_158
		and target_1.getRValue().(FunctionCall).getTarget().hasName("jbig2_get_uint32")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsegment_data_155)
}

predicate func_2(Parameter vsegment_data_155, VariableAccess target_2) {
		target_2.getTarget()=vsegment_data_155
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Parameter vsegment_data_155, Variable vend_row_158, AssignExpr target_3) {
		target_3.getLValue().(VariableAccess).getTarget()=vend_row_158
		and target_3.getRValue().(FunctionCall).getTarget().hasName("jbig2_get_int32")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsegment_data_155
}

from Function func, Parameter vsegment_data_155, Variable vend_row_158, VariableAccess target_2, AssignExpr target_3
where
not func_1(vsegment_data_155, vend_row_158)
and func_2(vsegment_data_155, target_2)
and func_3(vsegment_data_155, vend_row_158, target_3)
and vsegment_data_155.getType().hasName("const uint8_t *")
and vend_row_158.getType().hasName("int")
and vsegment_data_155.getParentScope+() = func
and vend_row_158.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
