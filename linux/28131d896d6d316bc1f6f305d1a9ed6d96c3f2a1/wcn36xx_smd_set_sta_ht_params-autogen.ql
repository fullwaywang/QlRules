/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_smd_set_sta_ht_params
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/wcn36xx-smd-set-sta-ht-params
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_smd_set_sta_ht_params CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsta_params_257) {
	exists(NotExpr target_0 |
		target_0.getOperand() instanceof FunctionCall
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="max_amsdu_size"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsta_params_257)
}

predicate func_1(Variable vcaps_260) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("is_cap_supported")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vcaps_260
		and target_1.getArgument(1).(Literal).getValue()="2048")
}

from Function func, Parameter vsta_params_257, Variable vcaps_260
where
not func_0(vsta_params_257)
and func_1(vcaps_260)
and vsta_params_257.getType().hasName("wcn36xx_hal_config_sta_params *")
and vcaps_260.getType().hasName("unsigned long")
and vsta_params_257.getParentScope+() = func
and vcaps_260.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
