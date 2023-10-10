/**
 * @name libxml2-0e1a49c8907645d2e155f0d89d4d9895ac5112b5-xmlStringLenDecodeEntities
 * @id cpp/libxml2/0e1a49c8907645d2e155f0d89d4d9895ac5112b5/xmlStringLenDecodeEntities
 * @description libxml2-0e1a49c8907645d2e155f0d89d4d9895ac5112b5-xmlStringLenDecodeEntities CVE-2020-7595
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_2610) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="instate"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2610)
}

predicate func_1(Parameter vend_2611, Parameter vend2_2611, Parameter vend3_2611, Variable vc_2620) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_2620
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_2620
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_2611
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_2620
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend2_2611
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vc_2620
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend3_2611)
}

predicate func_2(Parameter vctxt_2610, Parameter vstr_2610, Variable vl_2620) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("xmlStringCurrentChar")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctxt_2610
		and target_2.getArgument(1).(VariableAccess).getTarget()=vstr_2610
		and target_2.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_2620)
}

from Function func, Parameter vctxt_2610, Parameter vstr_2610, Parameter vend_2611, Parameter vend2_2611, Parameter vend3_2611, Variable vc_2620, Variable vl_2620
where
not func_0(vctxt_2610)
and func_1(vend_2611, vend2_2611, vend3_2611, vc_2620)
and vctxt_2610.getType().hasName("xmlParserCtxtPtr")
and func_2(vctxt_2610, vstr_2610, vl_2620)
and vstr_2610.getType().hasName("const xmlChar *")
and vend_2611.getType().hasName("xmlChar")
and vend2_2611.getType().hasName("xmlChar")
and vend3_2611.getType().hasName("xmlChar")
and vc_2620.getType().hasName("int")
and vl_2620.getType().hasName("int")
and vctxt_2610.getParentScope+() = func
and vstr_2610.getParentScope+() = func
and vend_2611.getParentScope+() = func
and vend2_2611.getParentScope+() = func
and vend3_2611.getParentScope+() = func
and vc_2620.getParentScope+() = func
and vl_2620.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
