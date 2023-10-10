/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-client_info_show
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/client-info-show
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-client_info_show 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vm_2479) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("file_inode")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="file"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vm_2479)
}

predicate func_2(Parameter vm_2479) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="private"
		and target_2.getQualifier().(VariableAccess).getTarget()=vm_2479)
}

from Function func, Parameter vm_2479
where
not func_0(vm_2479)
and func_2(vm_2479)
and vm_2479.getType().hasName("seq_file *")
and vm_2479.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
