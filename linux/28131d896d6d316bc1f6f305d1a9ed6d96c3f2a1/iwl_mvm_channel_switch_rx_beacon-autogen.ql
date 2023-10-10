/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_channel_switch_rx_beacon
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-channel-switch-rx-beacon
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_channel_switch_rx_beacon CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(SubExpr target_1 |
		target_1.getValue()="41"
		and target_1.getLeftOperand().(SizeofExprOperator).getValue()="43"
		and target_1.getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="Modify CSA on mac %d count = %d mode = %d\n"
		and target_1.getRightOperand().(Literal).getValue()="2"
		and target_1.getParent().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="Modify CSA on mac %d count = %d mode = %d\n"
		and target_1.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(StringLiteral target_4 |
		target_4.getValue()="Modify CSA on mac %d count = %d (old %d) mode = %d\n"
		and target_4.getEnclosingFunction() = func)
}

predicate func_6(Variable vmvmvif_4694) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="id"
		and target_6.getQualifier().(VariableAccess).getTarget()=vmvmvif_4694)
}

from Function func, Variable vmvmvif_4694
where
func_1(func)
and not func_4(func)
and vmvmvif_4694.getType().hasName("iwl_mvm_vif *")
and func_6(vmvmvif_4694)
and vmvmvif_4694.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
