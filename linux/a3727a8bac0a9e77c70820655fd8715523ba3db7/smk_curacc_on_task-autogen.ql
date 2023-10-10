/**
 * @name linux-a3727a8bac0a9e77c70820655fd8715523ba3db7-smk_curacc_on_task
 * @id cpp/linux/a3727a8bac0a9e77c70820655fd8715523ba3db7/smk-curacc-on-task
 * @description linux-a3727a8bac0a9e77c70820655fd8715523ba3db7-smk_curacc_on_task 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_2015) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("smk_of_task_struct_subj")
		and not target_0.getTarget().hasName("smk_of_task_struct_obj")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vp_2015)
}

from Function func, Parameter vp_2015
where
func_0(vp_2015)
and vp_2015.getType().hasName("task_struct *")
and vp_2015.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
