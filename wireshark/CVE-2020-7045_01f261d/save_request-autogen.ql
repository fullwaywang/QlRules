/**
 * @name wireshark-01f261de41f4dd3233ef578e5c0ffb9c25c7d14d-save_request
 * @id cpp/wireshark/01f261de41f4dd3233ef578e5c0ffb9c25c7d14d/save-request
 * @description wireshark-01f261de41f4dd3233ef578e5c0ffb9c25c7d14d-epan/dissectors/packet-btatt.c-save_request CVE-2020-7045
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("wmem_alloc")
		and not target_0.getTarget().hasName("wmem_alloc0")
		and target_0.getArgument(0).(FunctionCall).getTarget().hasName("wmem_file_scope")
		and target_0.getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getArgument(1).(SizeofTypeOperator).getValue()="40"
		and target_0.getEnclosingFunction() = func
}

from Function func, FunctionCall target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
