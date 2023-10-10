/**
 * @name linux-3a9b153c5591548612c3955c9600a98150c81875-mwifiex_ret_wmm_get_status
 * @id cpp/linux/3a9b153c5591548612c3955c9600a98150c81875/mwifiex-ret-wmm-get-status
 * @description linux-3a9b153c5591548612c3955c9600a98150c81875-mwifiex_ret_wmm_get_status 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwmm_param_ie_921) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="len"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vend_hdr"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwmm_param_ie_921
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SizeofTypeOperator).getValue()="26"
		and target_0.getThen().(BreakStmt).toString() = "break;")
}

predicate func_1(Variable vwmm_param_ie_921) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="qos_info_bitmap"
		and target_1.getQualifier().(VariableAccess).getTarget()=vwmm_param_ie_921)
}

from Function func, Variable vwmm_param_ie_921
where
not func_0(vwmm_param_ie_921)
and vwmm_param_ie_921.getType().hasName("ieee_types_wmm_parameter *")
and func_1(vwmm_param_ie_921)
and vwmm_param_ie_921.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
