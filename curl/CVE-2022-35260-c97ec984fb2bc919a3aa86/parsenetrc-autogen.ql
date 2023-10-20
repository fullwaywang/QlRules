/**
 * @name curl-c97ec984fb2bc919a3aa86-parsenetrc
 * @id cpp/curl/c97ec984fb2bc919a3aa86/parsenetrc
 * @description curl-c97ec984fb2bc919a3aa86-parsenetrc CVE-2022-35260
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfile_63, Variable vnetrcbuffer_82, Variable vnetrcbuffsize_83) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("fgets")
		and not target_0.getTarget().hasName("Curl_get_line")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnetrcbuffer_82
		and target_0.getArgument(1).(VariableAccess).getTarget()=vnetrcbuffsize_83
		and target_0.getArgument(2).(VariableAccess).getTarget()=vfile_63)
}

from Function func, Variable vfile_63, Variable vnetrcbuffer_82, Variable vnetrcbuffsize_83
where
func_0(vfile_63, vnetrcbuffer_82, vnetrcbuffsize_83)
and vfile_63.getType().hasName("FILE *")
and vnetrcbuffer_82.getType().hasName("char[4096]")
and vnetrcbuffsize_83.getType().hasName("int")
and vfile_63.getParentScope+() = func
and vnetrcbuffer_82.getParentScope+() = func
and vnetrcbuffsize_83.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
