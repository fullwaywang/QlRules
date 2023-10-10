/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath10k_core_copy_target_iram
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/ath10k-core-copy-target-iram
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath10k_core_copy_target_iram CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter var_2683) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ath10k_coredump_get_mem_layout")
		and not target_0.getTarget().hasName("_ath10k_coredump_get_mem_layout")
		and target_0.getArgument(0).(VariableAccess).getTarget()=var_2683)
}

predicate func_2(Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Parameter var_2683
where
func_0(var_2683)
and func_2(func)
and var_2683.getType().hasName("ath10k *")
and var_2683.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
